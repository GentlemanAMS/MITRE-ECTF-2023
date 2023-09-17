/**
 * @file main.c
 * @author Frederich Stine
 * @brief eCTF Fob Example Design Implementation
 * @date 2023
 *
 * This source file is part of an example system for MITRE's 2023 Embedded
 * System CTF (eCTF). This code is being provided only for educational purposes
 * for the 2023 MITRE eCTF competition, and may not meet MITRE standards for
 * quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2023 The MITRE Corporation
 */

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <stddef.h>
#include <ctype.h>


#include "tw/hw/hw_ints.h"
#include "tw/hw/hw_memmap.h"
#include "tw/hw/hw_nvic.h"

#include "tw/eeprom.h"
#include "tw/flash.h"
#include "tw/gpio.h"
#include "tw/interrupt.h"
#include "tw/pin_map.h"
#include "tw/sysctl.h"
#include "tw/timer.h"
#include "tw/uart.h"
#include "tw/mpu.h"

#include "messages.h"
#include "hw_rng.h"
#include "board_link.h"
#include "feature_list.h"
#include "uart.h"
#include "eeprom.h"
#include "eeprom_access.h"
#include "messages.h"
#include "crypto_wrappers.h"
#include "debug.h"
#include "timer_config.h"
#include "anti-glitching.h"

#include "monocypher.h"



uint8_t rand_key[HASH_BLOCK_SIZE_64];


volatile int fi_vol = -2;
volatile int rand_ret, rand_i, rand_y;
volatile uint8_t rand_rbt[16];


#ifdef DEBUG
void __error__(char *pcFilename, uint32_t ui32Line) {
    while (1) {
        __asm volatile ("nop");
    }
}
#endif

typedef stored_features_t FLASH_DATA;

#define BOARD_RECV_TIMEOUT_MS 500
#define HOST_RECV_TIMEOUT_MS 500

#define FOB_STATE_PTR 0x3FC00
#define FLASH_DATA_SIZE         \
  (sizeof(FLASH_DATA) % 4 == 0) \
      ? sizeof(FLASH_DATA)      \
      : sizeof(FLASH_DATA) + (4 - (sizeof(FLASH_DATA) % 4))
#define FLASH_PAIRED 0x00
#define FLASH_UNPAIRED 0xFF

/**
 * @brief Function that erases and rewrites the non-volatile data to flash
 *
 * @param info Pointer to the flash data ram
 */
void saveFobState(FLASH_DATA *flash_data)
{
  FlashErase(FOB_STATE_PTR);
  FlashProgram((uint32_t *)flash_data, FOB_STATE_PTR, FLASH_DATA_SIZE);
}

/**
 * @brief Stalling function to call after a failure
 * @param fob_state_ram - the current fob_state that holds fail_count
*/
void fail_stall_function(FLASH_DATA *fob_state_ram)
{
  if (fob_state_ram->fail_count < 3) 
  {
    fob_state_ram->fail_count += 1;
    saveFobState(fob_state_ram);
    normal_stall();
  } 
  else if (fob_state_ram->fail_count == 3) 
  {
    attacked_stall();
  } 
  else 
  {
    DEBUG_PRINT("fail_count surpassed 3; glitch occured\n");
    halt_and_catch_fire();
  }
  return;
}

/**
 * @brief Stalling function to call after a success
 * @param fob_state_ram - the current fob_state that holds fail_count
*/
void succ_stall_function(FLASH_DATA *fob_state_ram)
{
  fob_state_ram->fail_count = 0;
  saveFobState(fob_state_ram);
  normal_stall();
}


bool paired_fob_verify_pin() {
  DEBUG_PRINT("Enter pin: ");

  uint8_t pin[6];
  uart_read(HOST_UART, pin, sizeof(pin));

  for (int i = 0; i < 6; ++i) {
    pin[i] = toupper((unsigned char)pin[i]);

    bool is_alpha = ('A' <= pin[i]) && (pin[i] <= 'F');
    bool is_digit = ('0' <= pin[i]) && (pin[i] <= '9');

    FI_PROT_VOL((is_alpha || is_digit), BAD_BOOL);
    if (fi_vol != true) {
      // PIN must be entirely hex digits (either is_alpha or is_digit)
      return false;
    }
  }

  uint32_t pin_hash_key[64 / 4] = { 0 };
  eeprom_read(EDT_CAR_PIN_HASH_KEY, pin_hash_key, sizeof(pin_hash_key));

  uint8_t user_pin_hash[64] = { 0 };
  crypto_blake2b_general(user_pin_hash, 64, (const uint8_t*)pin_hash_key, 64, (const uint8_t*)pin, 6);

  crypto_wipe((void *)pin_hash_key, sizeof(pin_hash_key));

  uint32_t real_pin_hash[64 / 4] = { 0 };
  eeprom_read(EDT_CAR_PIN_HASH, real_pin_hash, sizeof(real_pin_hash));

  FI_PROT_VOL1((crypto_verify64(user_pin_hash, (const uint8_t *)real_pin_hash)),
                BAD_CRYP_CMP);

  crypto_wipe((void *)real_pin_hash, sizeof(real_pin_hash));
  crypto_wipe((void *)user_pin_hash, sizeof(user_pin_hash));

  FI_PROT_VOL2(BAD_CRYP_CMP);

  RAND_STALL_HALT();
  return (fi_vol == 0);
}

void paired_fob_pair() {
  prime_delay_timer();

  FLASH_DATA fob_state_ram;
  FLASH_DATA *fob_state_flash = (FLASH_DATA *)FOB_STATE_PTR;
  memcpy(&fob_state_ram, fob_state_flash, FLASH_DATA_SIZE);
  FI_PROT_VOL((paired_fob_verify_pin()), BAD_BOOL);

  if (fi_vol != true) {
    DEBUG_PRINT("Pairing Failure: PIN Incorrect\n");
    fail_stall_function(&fob_state_ram);
    return;
  }

  DEBUG_PRINT("Pairing Pass\n");

  fob_info_t fob_info;

  eeprom_read(EDT_CAR_ID, (uint32_t *)&fob_info.car_id, sizeof(fob_info.car_id));
  eeprom_read(EDT_CAR_E_PUBLIC_KEY, (uint32_t *)&fob_info.car_encryption_public_key, PUBLIC_KEY_LEN);
  eeprom_read(EDT_CAR_S_PUBLIC_KEY, (uint32_t *)&fob_info.car_signature_public_key, PUBLIC_KEY_LEN);
  eeprom_read(EDT_DEPLOYMENT_S_PUBLIC_KEY, (uint32_t *)&fob_info.deployment_signature_public_key, PUBLIC_KEY_LEN);
  eeprom_read(EDT_UPF_E_PUBLIC_KEY, (uint32_t *)&fob_info.unpaired_fob_encryption_public_key, PUBLIC_KEY_LEN);
  eeprom_read(EDT_PF_E_PRIVATE_KEY, (uint32_t *)&fob_info.paired_fob_encryption_private_key, PRIVATE_KEY_LEN);
  eeprom_read(EDT_PF_S_PRIVATE_KEY, (uint32_t *)&fob_info.paired_fob_signature_private_key, PRIVATE_KEY_LEN);
  eeprom_read(EDT_CAR_PIN_HASH, (uint32_t *)&fob_info.pin_hash, HASH_LEN);
  eeprom_read(EDT_CAR_PIN_HASH_KEY, (uint32_t *)&fob_info.pin_hash_key, HASH_LEN);

  clone_fob_message_t clone_fob_message;
  clone_fob_message.message_type = MSG_PAIR_SEND;

  uint8_t nonce[64] = { 0 };
  // If the RNG returns -1, there was a fault attack
  FI_PROT_VOL((generateRNGBytes64(nonce)), BAD_RNG);

  uint32_t upf_pub_key[PUBLIC_KEY_LEN / 4] = { 0 };
  eeprom_read(EDT_UPF_E_PUBLIC_KEY, upf_pub_key, PUBLIC_KEY_LEN);
  FI_PROT_VOL1((cc_encrypt_asymmetric(
    clone_fob_message.encrypted_fob_info,
    (uint8_t *)&fob_info,
    sizeof(fob_info_t),
    (uint8_t *)upf_pub_key,
    nonce)), BAD_ENCRYPT);

  
  crypto_wipe((void *)&fob_info, sizeof(fob_info_t));
  crypto_wipe((void *)&upf_pub_key, sizeof(upf_pub_key));

  FI_PROT_VOL2(BAD_ENCRYPT);

  uart_write(BOARD_UART, (uint8_t *)&clone_fob_message, sizeof(clone_fob_message));
  succ_stall_function(&fob_state_ram);
}

int paired_fob_enable_impl(FLASH_DATA *fob_state_ram)
{
  // read fob pairing status from eeprom

  uint32_t is_paired_fob = 0;
  eeprom_read(EDT_IS_PAIRED_FOB, (uint32_t *)&is_paired_fob, sizeof(uint32_t));

  RAND_STALL_HALT();
  if (is_paired_fob != true)
  {
    // This function should never be called from an unpaired fob.
    halt_and_catch_fire();
    return 1;
  }

 
  enable_feature_message_t enable_message;
  if (receive_message_nonblocking((uint8_t *)&enable_message, sizeof(enable_feature_message_t), HOST_RECV_TIMEOUT_MS, HOST_UART) < 0) {
    DEBUG_PRINT("Timed out waiting for feature");
    return 1;
  }

  /**
    * check signature with deployment key
    **/

  // read deployment public key from eeprom
  uint32_t depl_pub_key[PUBLIC_KEY_LEN / 4];
  eeprom_read(EDT_DEPLOYMENT_S_PUBLIC_KEY, depl_pub_key, PUBLIC_KEY_LEN);

  FI_PROT_VOL1((cc_verify_asymmetric(
    enable_message.feature.signature,
    (uint8_t *)&enable_message.feature,
    sizeof(enable_message.feature.car_id) + sizeof(enable_message.feature.feature_number),
    (uint8_t *)depl_pub_key) == 0), BAD_BOOL);

  crypto_wipe((void *)depl_pub_key, sizeof(depl_pub_key));

  FI_PROT_VOL2(BAD_BOOL);

  if (fi_vol != true) {
    // Check failed, skip enabling actions
    DEBUG_PRINT("Feature did not verify successfully\n");
    return 1;
  }

  volatile uint32_t package_feature_number = INVALID_FEATURE;
  package_feature_number = enable_message.feature.feature_number;
  FI_PROT_VOL((package_feature_number != INVALID_FEATURE), BAD_BOOL);
  if (fi_vol != true) halt_and_catch_fire();


  uint32_t fob_car_id = INVALID_CAR_ID;
  eeprom_read(EDT_CAR_ID, (uint32_t*)&fob_car_id, sizeof(fob_car_id));

  if (fob_car_id == INVALID_CAR_ID) {
    crypto_wipe(&fob_car_id, sizeof(fob_car_id));
    halt_and_catch_fire();
    return 1;
  }

  FI_PROT_VOL1((fob_car_id == enable_message.feature.car_id), BAD_BOOL);
  
  crypto_wipe(&fob_car_id, sizeof(fob_car_id));

  FI_PROT_VOL2(BAD_BOOL);

  if (fi_vol != true) {
    DEBUG_PRINT("Feature did not have correct car ID\n");
    return 1;
  }


  FI_PROT_VOL((package_feature_number == 1 || 
               package_feature_number == 2 || 
               package_feature_number == 3), BAD_BOOL);
  if (fi_vol != true) {
    // Out-of-range features should report as "enabled" but don't actually do anything.
    return 0;
  }

  uint32_t active = 0;
  eeprom_read(EDT_FEATURE_BITVEC, (uint32_t *)&active, sizeof(uint32_t));

  /**
    * Ensure the feature isn't already enabled
    */

  RAND_STALL_HALT();
  if (active & (1 << (package_feature_number - 1))) {
    // Feature enabled already
    return 0;
  }

  /**
    * save feature package
    */

  fob_state_ram->features_array[package_feature_number - 1] = enable_message.feature;
  // show feature activated in active_feature
  active |= 1 << (package_feature_number - 1);

  eeprom_write(EDT_FEATURE_BITVEC, &active,sizeof(uint32_t));
  saveFobState(fob_state_ram);

  return 0;
}

void paired_fob_enable(FLASH_DATA *fob_state_ram) {
  prime_delay_timer();

  FI_PROT_VOL((paired_fob_enable_impl(fob_state_ram) == 0), BAD_BOOL);

  if (fi_vol == true) {
    succ_stall_function(fob_state_ram);
    uart_write(HOST_UART, (uint8_t *)"Enabled", 7);
  }else {
    fail_stall_function(fob_state_ram);
    uart_write(HOST_UART, (uint8_t *)"Failed ", 7);
  }
}


// returns 1 on error, 0 on success
int paired_fob_unlock_impl(FLASH_DATA *fob_state_ram) {
  // step 0: discard any extra bytes that may have come in
  while (UARTCharsAvail(BOARD_UART)) {
    UARTCharGet(BOARD_UART);
  }

  // step 1: send unlock msg
  unlock_message_t unlock_msg;
  unlock_msg.message_type = MSG_UNLOCK_START;
  uart_write(BOARD_UART, (uint8_t *)&unlock_msg, sizeof(unlock_message_t));

  // step 2: receive nonce
  challenge_message_t challenge_msg;
  if (receive_message_nonblocking((uint8_t *)&challenge_msg, sizeof(challenge_message_t), BOARD_RECV_TIMEOUT_MS, BOARD_UART) < 0)
  {
    DEBUG_PRINT("Unlock receive timed out\n");
    return 1;
  }
  FI_PROT_VOL((challenge_msg.message_type == MSG_UNLOCK_CHALLENGE), BAD_BOOL);
  if (fi_vol != true) {
    return 1;
  }
  DEBUG_PRINT("Paired fob received unlock challenge\n");

  challenge_t challenge;

  uint32_t paired_fob_encryption_private_key[PRIVATE_KEY_LEN / 4];
  eeprom_read(EDT_PF_E_PRIVATE_KEY, paired_fob_encryption_private_key, PRIVATE_KEY_LEN);
  FI_PROT_VOL1((cc_decrypt_asymmetric(
    (uint8_t *)&challenge,
    challenge_msg.encrypted_challenge,
    sizeof(challenge_t),
    (uint8_t *)paired_fob_encryption_private_key)), BAD_DECRYPT);

  crypto_wipe((void *)paired_fob_encryption_private_key, sizeof(paired_fob_encryption_private_key));

  FI_PROT_VOL2(BAD_DECRYPT);

  if(fi_vol != 0 && fi_vol != -1){
    halt_and_catch_fire();
    return 1;
  }

  RAND_STALL_HALT();
  if (fi_vol == -1)
  {
    return 1;
  }

  // step 2.5: validate the car's signature on the challenge.
  uint32_t car_signature_public_key[PUBLIC_KEY_LEN / 4];
  eeprom_read(EDT_CAR_S_PUBLIC_KEY, car_signature_public_key, PUBLIC_KEY_LEN);
  FI_PROT_VOL1((cc_verify_asymmetric(
    challenge.signed_nonce,
    (uint8_t *)&challenge.nonce,
    sizeof(challenge.nonce),
    (uint8_t *)car_signature_public_key)), BAD_VERIFY);
  
  crypto_wipe((void *)car_signature_public_key, sizeof(car_signature_public_key));

  FI_PROT_VOL2(BAD_VERIFY);

  if (fi_vol != 0 && fi_vol != -1) {
    halt_and_catch_fire();
    return 1;
  }

  RAND_STALL_HALT();
  if (fi_vol == -1)
  {
    return 1;
  }
  uint64_t nonce = challenge.nonce;

  crypto_wipe((void *)&challenge, sizeof(challenge_t));

  // step 3: sign the nonce & features
  response_t response;
  memset((uint8_t *)&response.body, 0, sizeof(response)); 

  response.body.nonce = nonce;
  response.body.message_type = MSG_UNLOCK_RESPONSE;

  uint32_t active = 0;
  eeprom_read(EDT_FEATURE_BITVEC, (uint32_t *)&active, sizeof(uint32_t));
  response.body.active_features = active & 0xff;

  FLASH_DATA *fob_state_flash = (FLASH_DATA *)FOB_STATE_PTR;
  memcpy(fob_state_ram, fob_state_flash, FLASH_DATA_SIZE);
  memcpy((uint8_t *)response.body.signed_features, (uint8_t *)fob_state_ram->features_array, sizeof(response.body.signed_features));

  uint32_t paired_fob_signature_private_key[PRIVATE_KEY_LEN / 4];
  eeprom_read(EDT_PF_S_PRIVATE_KEY, paired_fob_signature_private_key, PRIVATE_KEY_LEN);

  FI_PROT_VOL1((cc_sign_asymmetric(
    (uint8_t *)response.signature,
    (uint8_t *)&response.body,
    sizeof(response.body),
    (uint8_t *)paired_fob_signature_private_key)), BAD_SIGN);

  crypto_wipe((void *)paired_fob_signature_private_key,
              sizeof(paired_fob_signature_private_key));

  // If our signature failed right after creating it, HW attack
  FI_PROT_VOL2(BAD_SIGN);

  // step 4: encrypt and send the response
  response_message_t response_msg;
  response_msg.message_type = MSG_UNLOCK_RESPONSE;

  uint8_t rand_buffer[64];
  FI_PROT_VOL((generateRNGBytes64(rand_buffer)), BAD_RNG);

  uint32_t car_encryption_public_key[PUBLIC_KEY_LEN / 4];
  eeprom_read(EDT_CAR_E_PUBLIC_KEY, car_encryption_public_key, PUBLIC_KEY_LEN);
  FI_PROT_VOL1((cc_encrypt_asymmetric(
    response_msg.encrypted_response,
    (uint8_t *)&response,
    sizeof(response),
    (uint8_t *)car_encryption_public_key,
    rand_buffer)), BAD_ENCRYPT);
  crypto_wipe((void *)car_encryption_public_key, sizeof(car_encryption_public_key));

  FI_PROT_VOL2(BAD_ENCRYPT);

  uint32_t deployment_signature_public_key[PUBLIC_KEY_LEN / 4];
  eeprom_read(EDT_DEPLOYMENT_S_PUBLIC_KEY, (uint32_t *)deployment_signature_public_key, PUBLIC_KEY_LEN);

  uint32_t car_id = INVALID_CAR_ID;
  eeprom_read(EDT_CAR_ID, &car_id, sizeof(uint32_t));

  RAND_STALL_HALT();
  if (car_id == INVALID_CAR_ID) {
    crypto_wipe((void *)deployment_signature_public_key, sizeof(deployment_signature_public_key));
    crypto_wipe((void *)&response, sizeof(response));
    halt_and_catch_fire();
    return 1;
  }

  bool features_are_ok = true;

  for (int i = 0; i < MAX_NUM_FEATURES; i++)
  {
    if ((active & (1 << i)) != 0)
    {
      feature_t *feature = &response.body.signed_features[i];

      FI_PROT_VOL1((cc_verify_asymmetric(
        feature->signature,
        (uint8_t *)feature,
        8,
        (uint8_t *)deployment_signature_public_key)), BAD_VERIFY);
      
      if (fi_vol != 0 && fi_vol != -1)
      {
        crypto_wipe((void *)deployment_signature_public_key, sizeof(deployment_signature_public_key));
        crypto_wipe((void *)&response, sizeof(response));
        halt_and_catch_fire();
        return 1;
      }

      RAND_STALL_HALT();
      if (fi_vol != 0)
      {
        DEBUG_PRINT("feature verification failed: invalid feature\n");
        features_are_ok = false;
      }

      FI_PROT_VOL((car_id == feature->car_id), BAD_BOOL);
      if (fi_vol != true) {
        DEBUG_PRINT("feature verification failed: feature car ID mismatch\n");
        features_are_ok = false;
      }

      FI_PROT_VOL((i+1 == feature->feature_number), BAD_BOOL);
      if (fi_vol != true) {
        DEBUG_PRINT("feature verification kfailed: feature number mismatch\n");
        features_are_ok = false;
      }
    }
  }

  crypto_wipe((void *)deployment_signature_public_key, sizeof(deployment_signature_public_key));
  crypto_wipe((void *)&response, sizeof(response));

  FI_PROT_VOL((features_are_ok == true), BAD_BOOL);
  if (fi_vol != true) {
    return 1;
  }

  DEBUG_PRINT("All features verified right before sending.\n");

  send_board_message((uint8_t *)&response_msg, sizeof(response_message_t));
  return 0;
}

void paired_fob_unlock(FLASH_DATA *fob_state_ram) {
  prime_delay_timer();
  FI_PROT_VOL((paired_fob_unlock_impl(fob_state_ram) == 0), BAD_BOOL);

  if (fi_vol == true) {
    succ_stall_function(fob_state_ram);
  }else {
    fail_stall_function(fob_state_ram);
  }
}

void paired_fob_main() {
  FLASH_DATA fob_state_ram;
  FLASH_DATA *fob_state_flash = (FLASH_DATA *)FOB_STATE_PTR;
  memcpy(&fob_state_ram, fob_state_flash, FLASH_DATA_SIZE);

  RAND_STALL_HALT();
  if (fob_state_ram.active_features == 0xff)
  {
    memset(&fob_state_ram,0,FLASH_DATA_SIZE);
    saveFobState(&fob_state_ram);
  }

  uint8_t previous_sw_state = GPIO_PIN_4;
  uint8_t debounce_sw_state = GPIO_PIN_4;
  uint8_t current_sw_state = GPIO_PIN_4;

  while (1) {
    int32_t found_char = UARTCharGetNonBlocking(HOST_UART);
    if (found_char == 'p') {
      paired_fob_pair();
    } else if (found_char == 'e') {
      paired_fob_enable(&fob_state_ram);
    }

    current_sw_state = GPIOPinRead(GPIO_PORTF_BASE, GPIO_PIN_4);
    if ((current_sw_state != previous_sw_state) && (current_sw_state == 0))
    {
      // Debounce switch
      for (int i = 0; i < 10000; i++)
        ;
      debounce_sw_state = GPIOPinRead(GPIO_PORTF_BASE, GPIO_PIN_4);
      if (debounce_sw_state == current_sw_state)
      {
        paired_fob_unlock(&fob_state_ram);
      }
    }
    previous_sw_state = current_sw_state;

  }

  // Unreachable.
  halt_and_catch_fire();
}

void unpaired_fob_pair() {
  clone_fob_message_t clone_fob_message;

  // Discard junk bytes that may have appeared on the UART.
  while (1) {
    receive_board_message(&clone_fob_message.message_type, 1);

    if (clone_fob_message.message_type == MSG_PAIR_SEND) {
      break;
    }
  }

  prime_delay_timer();

  if (receive_message_nonblocking(clone_fob_message.encrypted_fob_info,
      sizeof(clone_fob_message.encrypted_fob_info), BOARD_RECV_TIMEOUT_MS, BOARD_UART) < 0)
  {
    normal_stall();
    uart_write(HOST_UART, (uint8_t *)"Failed", 6);
    return;
  }

  fob_info_t fob_info;
  uint32_t upf_priv_key[PRIVATE_KEY_LEN / 4] = { 0 };
  eeprom_read(EDT_UPF_E_PRIVATE_KEY, upf_priv_key, PRIVATE_KEY_LEN);
  FI_PROT_VOL1((cc_decrypt_asymmetric(
    (uint8_t*)&fob_info,
    clone_fob_message.encrypted_fob_info,
    sizeof(fob_info_t),
    (uint8_t *)upf_priv_key)), BAD_DECRYPT);
  
  crypto_wipe((void *)upf_priv_key, sizeof(upf_priv_key));

  FI_PROT_VOL2(BAD_DECRYPT);

  if (fi_vol != 0) {
    normal_stall();
    uart_write(HOST_UART, (uint8_t *)"Failed", 6);
    return;
  }

  eeprom_write(EDT_CAR_ID, (uint32_t*)&fob_info.car_id, sizeof(fob_info.car_id));
  eeprom_write(EDT_CAR_E_PUBLIC_KEY, (uint32_t*)&fob_info.car_encryption_public_key, PUBLIC_KEY_LEN);
  eeprom_write(EDT_CAR_S_PUBLIC_KEY, (uint32_t*)&fob_info.car_signature_public_key, PUBLIC_KEY_LEN);
  eeprom_write(EDT_DEPLOYMENT_S_PUBLIC_KEY, (uint32_t*)&fob_info.deployment_signature_public_key, PUBLIC_KEY_LEN);
  eeprom_write(EDT_UPF_E_PUBLIC_KEY, (uint32_t *)&fob_info.unpaired_fob_encryption_public_key, PUBLIC_KEY_LEN);
  eeprom_write(EDT_PF_E_PRIVATE_KEY, (uint32_t*)&fob_info.paired_fob_encryption_private_key, PRIVATE_KEY_LEN);
  eeprom_write(EDT_PF_S_PRIVATE_KEY, (uint32_t*)&fob_info.paired_fob_signature_private_key, PRIVATE_KEY_LEN);
  eeprom_write(EDT_CAR_PIN_HASH, (uint32_t*)&fob_info.pin_hash, HASH_LEN);
  eeprom_write(EDT_CAR_PIN_HASH_KEY, (uint32_t*)&fob_info.pin_hash_key, HASH_LEN);

  crypto_wipe(&fob_info, sizeof(fob_info));

  uint32_t is_paired = 1;
  eeprom_write(EDT_IS_PAIRED_FOB, (uint32_t*)&is_paired, sizeof(is_paired));


  uint32_t active = 0;
  eeprom_write(EDT_FEATURE_BITVEC, (uint32_t*)&active, sizeof(active));
  normal_stall();
  uart_write(HOST_UART, (uint8_t *)"Paired", 6);

  paired_fob_main();
}

void unpaired_fob_main() {
  while (1) {
    int32_t found_char = UARTCharGetNonBlocking(HOST_UART);
    if (found_char == 'p') {
      unpaired_fob_pair();
    }
  }

  // Unreachable.
  halt_and_catch_fire();
}

/**
 * @brief Main function for the fob example
 *
 * Listens over UART and SW1 for an unlock command. If unlock command presented,
 * attempts to unlock door. Listens over UART for pair command. If pair
 * command presented, attempts to either pair a new key, or be paired
 * based on firmware build.
 */
int main(void)
{
  // 80 MHz clock frequency.
  SysCtlClockSet(SYSCTL_SYSDIV_2_5 | SYSCTL_USE_PLL | SYSCTL_XTAL_16MHZ | SYSCTL_OSC_INT);

  FI_PROT_VOL_WEAK((init_timers() == 0), BAD_BOOL);
  if (fi_vol != true) {
    halt_and_catch_fire();
  }

  prime_delay_timer();

  // 0x08000 to 0x10000 - Our firmware (executable, read-only)
  MPURegionSet(0, 0x8000, MPU_RGN_SIZE_32K | MPU_RGN_PERM_EXEC | MPU_RGN_PERM_PRV_RO_USR_NO | MPU_RGN_ENABLE);
  // 0x10000 to 0x20000 - Also our firmware (executable, read-only)
  MPURegionSet(1, 0x10000, MPU_RGN_SIZE_64K | MPU_RGN_PERM_EXEC | MPU_RGN_PERM_PRV_RO_USR_NO | MPU_RGN_ENABLE );
  // 0x20000 to 0x24000 - Flash padding for OTP (no-execute, read-only)
  MPURegionSet(2, 0x20000, MPU_RGN_SIZE_16K | MPU_RGN_PERM_NOEXEC | MPU_RGN_PERM_PRV_RO_USR_NO | MPU_RGN_ENABLE );
  // 0x3FC00 to 0x40000 - Flash storage for fob state
  MPURegionSet(3, 0x3FC00, MPU_RGN_SIZE_1K | MPU_RGN_PERM_NOEXEC | MPU_RGN_PERM_PRV_RO_USR_NO | MPU_RGN_ENABLE );
  // 0x2000_0000 to 0x2000_8000 - SRAM
  MPURegionSet(4, 0x20000000, MPU_RGN_SIZE_32K | MPU_RGN_PERM_NOEXEC | MPU_RGN_PERM_PRV_RW_USR_NO | MPU_RGN_ENABLE );
  // 0x4000_0000 to 0x8000_0000 - MMIO peripherals
  MPURegionSet(5, 0x40000000, MPU_RGN_SIZE_1G | MPU_RGN_PERM_NOEXEC | MPU_RGN_PERM_PRV_RW_USR_NO | MPU_RGN_ENABLE );
  // Enable the MMU.
  MPUEnable(MPU_CONFIG_HARDFLT_NMI);

  // Initialize UART
  uart_init();

  // Initialize board link UART
  setup_board_link();

  // Setup SW1
  GPIOPinTypeGPIOInput(GPIO_PORTF_BASE, GPIO_PIN_4);
  GPIOPadConfigSet(GPIO_PORTF_BASE, GPIO_PIN_4, GPIO_STRENGTH_4MA,
                   GPIO_PIN_TYPE_STD_WPU);

  SysCtlPeripheralEnable(SYSCTL_PERIPH_EEPROM0);

  FI_PROT_VOL_WEAK((EEPROMInit() == EEPROM_INIT_OK), BAD_BOOL);
  if (fi_vol != true) {
    DEBUG_PRINT("EEPROMInit failed\n");
    halt_and_catch_fire();
    return 1;
  }

  // Initialize thermal ADC
  // key into the hash is the first 64 bytes
  uint32_t eeprom_rng_seed_key[HASH_BLOCK_SIZE_64 / 4];
  EEPROMRead(eeprom_rng_seed_key, EEPROM_RNG_SEED, HASH_BLOCK_SIZE_64);
  // the rest is the random bytes that will be hashed
  uint32_t eeprom_rng_seed_len = EEPROM_RNG_SEED_SIZE - HASH_BLOCK_SIZE_64;
  uint32_t eeprom_rng_seed[eeprom_rng_seed_len / 4];
  EEPROMRead(eeprom_rng_seed, EEPROM_RNG_SEED + HASH_BLOCK_SIZE_64, eeprom_rng_seed_len);
  // hash into 64 bytes
  cc_hash_internal(
    rand_key,
    HASH_BLOCK_SIZE_64,
    (uint8_t*)eeprom_rng_seed,
    eeprom_rng_seed_len,
    (uint8_t *)eeprom_rng_seed_key,
    HASH_BLOCK_SIZE_64,
    CC_HASH_ITERS);
  
  FI_PROT_VOL_WEAK((generateRNGInit(rand_key)), BAD_RNG);
  if (fi_vol != 0)
  {
    halt_and_catch_fire();
    return 1;
  }

  uint32_t buf[1] = { 0 };

  eeprom_read(EDT_IS_PAIRED_FOB, buf, sizeof(buf));

  normal_stall();
  FI_PROT_VOL((buf[0] == 1), BAD_BOOL);
  if (fi_vol == true) {
    DEBUG_PRINT("Starting paired_fob_main\n");
    paired_fob_main();
  }
  FI_PROT_VOL((buf[0] == 0), BAD_BOOL);
  if (fi_vol == true) {
    DEBUG_PRINT("Starting unpaired_fob_main\n");
    unpaired_fob_main();
  }
  // This is unreachable because paired_fob_main and unpaired_fob_main never return.
  DEBUG_PRINT("EEPROM corrupted\n");
  // EEPROM must be corrupted if buf[0] != 0 or 1, or we're being glitched
  halt_and_catch_fire();
  return 1;
}
