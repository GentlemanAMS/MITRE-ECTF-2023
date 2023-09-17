#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stddef.h>
#include <ctype.h>

#include "tw/hw/hw_ints.h"
#include "tw/hw/hw_memmap.h"
#include "tw/hw/hw_types.h"

#include "tw/eeprom.h"
#include "tw/gpio.h"
#include "tw/flash.h"
#include "tw/interrupt.h"
#include "tw/pin_map.h"
#include "tw/sysctl.h"
#include "tw/timer.h"
#include "tw/mpu.h"

#include "board_link.h"
#include "feature_list.h"
#include "uart.h"
#include "hw_rng.h"
#include "eeprom.h"
#include "eeprom_access.h"
#include "messages.h"
#include "debug.h"
#include "crypto_wrappers.h"
#include "timer_config.h"
#include "anti-glitching.h"

#include "monocypher.h"



volatile int fi_vol = -2;
volatile int rand_ret, rand_i, rand_y;
volatile uint8_t rand_rbt[16];


uint8_t rand_key[HASH_BLOCK_SIZE_64];

typedef stored_features_t FLASH_DATA;

#define BOARD_RECV_TIMEOUT_MS 500

#define CAR_STATE_PTR 0x3FC00
#define FLASH_DATA_SIZE         \
  (sizeof(FLASH_DATA) % 4 == 0) \
      ? sizeof(FLASH_DATA)      \
      : sizeof(FLASH_DATA) + (4 - (sizeof(FLASH_DATA) % 4))


/**
 * @brief Function that erases and rewrites the non-volatile data to flash.
 *
 * @param info Pointer to the flash data ram.
 */
void saveCarState(FLASH_DATA *flash_data)
{
  FlashErase(CAR_STATE_PTR);
  FlashProgram((uint32_t *)flash_data, CAR_STATE_PTR, FLASH_DATA_SIZE);
}


#ifdef DEBUG
void __error__(char *pcFilename, uint32_t ui32Line) {
    while (1) {
        __asm volatile ("nop");
    }
}
#endif

/**
 * @brief Stalling function to call after a failure
 * @param car_state_ram - the current car_state that holds fail_count
*/
void fail_stall_function(FLASH_DATA *car_state_ram)
{
  if (car_state_ram->fail_count < 3) 
  {
    car_state_ram->fail_count += 1;
    saveCarState(car_state_ram);
    normal_stall();
  } 
  else if (car_state_ram->fail_count == 3) 
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
 * @param car_state_ram - the current car_state that holds fail_count
*/
void succ_stall_function(FLASH_DATA *car_state_ram)
{
  car_state_ram->fail_count = 0;
  saveCarState(car_state_ram);
  normal_stall();
}


// Returns zero on success, non-zero on failure.
int car_unlock() {
  // Step 1: create the challenge for the paired fob.
  uint8_t rand_buffer[64];
  FI_PROT_VOL((generateRNGBytes64(rand_buffer)), BAD_RNG);
  uint64_t nonce = 0;
  memcpy((uint8_t *)&nonce, rand_buffer, sizeof(nonce));

  challenge_t challenge;
  challenge.nonce = nonce;

  uint32_t car_signature_private_key[PRIVATE_KEY_LEN / 4];
  eeprom_read(EDT_CAR_S_PRIVATE_KEY, car_signature_private_key, PRIVATE_KEY_LEN);

  // Verifying that the signature is right
  FI_PROT_VOL1((cc_sign_asymmetric(challenge.signed_nonce, 
                (uint8_t *)&challenge.nonce, 
                sizeof(challenge.nonce), 
                (uint8_t *)car_signature_private_key)), BAD_SIGN);

  crypto_wipe((void *)car_signature_private_key,  
              sizeof(car_signature_private_key));

  FI_PROT_VOL2(BAD_SIGN);

  if (fi_vol != 0)
  {
    // A signature that was just generated failed?
    // May cpu/memory bugs or attack.
    halt_and_catch_fire();
    return 1;
  }

  // Step 2: encrypt and send the challenge for the paired fob

  FI_PROT_VOL((generateRNGBytes64(rand_buffer)), BAD_RNG);

  challenge_message_t challenge_msg;
  challenge_msg.message_type = MSG_UNLOCK_CHALLENGE;

  uint32_t paired_fob_encryption_public_key[PUBLIC_KEY_LEN / 4];
  eeprom_read(EDT_PF_E_PUBLIC_KEY, (uint32_t *)paired_fob_encryption_public_key, PUBLIC_KEY_LEN);
  FI_PROT_VOL1((cc_encrypt_asymmetric(
    challenge_msg.encrypted_challenge,
    (uint8_t *)&challenge,
    sizeof(challenge_t),
    (uint8_t *)paired_fob_encryption_public_key,
    rand_buffer)), BAD_ENCRYPT);

  crypto_wipe((void *)paired_fob_encryption_public_key, sizeof(paired_fob_encryption_public_key));
  crypto_wipe((void *)&challenge, sizeof(challenge));

  FI_PROT_VOL2(BAD_ENCRYPT);

  uart_write(BOARD_UART, (uint8_t *)&challenge_msg, sizeof(challenge_message_t));

  DEBUG_PRINT("Sent challenge\n");

  // Step 3: Receive and decrypt the response from the paired fob.

  RAND_STALL_HALT();
  response_message_t response_msg;
  if (receive_message_nonblocking((uint8_t *)&response_msg, sizeof(response_message_t), BOARD_RECV_TIMEOUT_MS, BOARD_UART) < 0)
  {
    DEBUG_PRINT("UART timed out while waiting for challenge response\n");
   
    return 1;
  }

  RAND_STALL_HALT();
  if (response_msg.message_type != MSG_UNLOCK_RESPONSE) {
    DEBUG_PRINT("Unlock failed: wrong message type\n");
    return 1;
  }

  response_t response;
  uint32_t car_encryption_private_key[PRIVATE_KEY_LEN / 4];
  eeprom_read(EDT_CAR_E_PRIVATE_KEY, (uint32_t *)car_encryption_private_key, PRIVATE_KEY_LEN);
  FI_PROT_VOL1((cc_decrypt_asymmetric(
    (uint8_t *)&response,
    response_msg.encrypted_response,
    sizeof(response),
    (uint8_t *)car_encryption_private_key)), BAD_DECRYPT);
  
  crypto_wipe((void *)car_encryption_private_key, sizeof(car_encryption_private_key));
  
  FI_PROT_VOL2(BAD_DECRYPT);

  RAND_STALL_HALT();
  if (fi_vol != 0) {
    DEBUG_PRINT("Unlock failed: decryption error\n");
    return 1;
  }

  // Step 4: Verify that the response's body is signed by the paired fob.
  RAND_STALL_HALT();
  if (response.body.message_type != MSG_UNLOCK_RESPONSE) {
    DEBUG_PRINT("Unlock failed: wrong body message type");
    return 1;
  }

  uint32_t paired_fob_signature_public_key[PUBLIC_KEY_LEN / 4];
  eeprom_read(EDT_PF_S_PUBLIC_KEY, (uint32_t *)paired_fob_signature_public_key, PUBLIC_KEY_LEN);
  FI_PROT_VOL1((cc_verify_asymmetric(
    response.signature,
    (uint8_t *)&response.body,
    sizeof(response.body),
    (uint8_t *)paired_fob_signature_public_key)), BAD_VERIFY);
  
  crypto_wipe((void *)paired_fob_signature_public_key, sizeof(paired_fob_signature_public_key));

  FI_PROT_VOL2(BAD_VERIFY);

  RAND_STALL_HALT();
  if (fi_vol != 0) {
    DEBUG_PRINT("Unlock failed: incorrect signature");
    return 1;
  }

  FI_PROT_VOL((response.body.nonce == nonce), BAD_BOOL);
  RAND_STALL_HALT();
  if (fi_vol != true) {
    DEBUG_PRINT("Unlock failed: incorrect nonce");
    return 1;
  }

  // Step 5: Verify that the response has valid features.
  uint8_t actives = response.body.active_features;
  
  RAND_STALL_HALT();
  if ((actives & 0xF8) != 0) {
    DEBUG_PRINT("Unlock failed: invalid active feature set\n");
    return 1;
  }

  uint32_t deployment_signature_public_key[PUBLIC_KEY_LEN / 4];
  eeprom_read(EDT_DEPLOYMENT_S_PUBLIC_KEY, (uint32_t *)deployment_signature_public_key, PUBLIC_KEY_LEN);

  uint32_t car_id = INVALID_CAR_ID;
  eeprom_read(EDT_CAR_ID, &car_id, sizeof(uint32_t));

  FI_PROT_VOL((car_id != INVALID_CAR_ID), BAD_BOOL);
  if (fi_vol != true)
  {
    halt_and_catch_fire();
    return 1;
  }

  bool features_are_ok = true;

  for (int i = 0; i < MAX_NUM_FEATURES; i++)
  {
    if ((actives & (1 << i)) != 0)
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
        DEBUG_PRINT("Unlock failed: invalid feature\n");
        features_are_ok = false;
      }

      FI_PROT_VOL((car_id == feature->car_id), BAD_BOOL);
      if (fi_vol != true) {
        DEBUG_PRINT("Unlock failed: feature car ID mismatch\n");
        features_are_ok = false;
      }

      FI_PROT_VOL((i+1 == feature->feature_number), BAD_BOOL);
      if (fi_vol != true) {
        DEBUG_PRINT("Unlock failed: feature number mismatch\n");
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

  // Step 6: Unlock and start the car.
  static const uint32_t feature_msg_base[3] = {
      EDT_FEATURE_MESSAGE_1,
      EDT_FEATURE_MESSAGE_2,
      EDT_FEATURE_MESSAGE_3,
  };

  uint32_t eeprom_message[EEPROM_MESSAGE_LEN / 4];
  eeprom_read(EDT_UNLOCK_MESSAGE, eeprom_message, EEPROM_MESSAGE_LEN);
  uart_write(HOST_UART, (uint8_t *)eeprom_message, EEPROM_MESSAGE_LEN);
  crypto_wipe((void *)eeprom_message, sizeof(eeprom_message));
  uart_writeb(HOST_UART, '\n');

  RAND_STALL_HALT();
  for (int i = 0; i < MAX_NUM_FEATURES; i++)
  {
    if ((actives & (1 << i)) != 0)
    {
      eeprom_read(feature_msg_base[i], eeprom_message, EEPROM_MESSAGE_LEN);
      uart_write(HOST_UART, (uint8_t *)eeprom_message, EEPROM_MESSAGE_LEN);
      crypto_wipe((void *)eeprom_message, sizeof(eeprom_message));
      uart_writeb(HOST_UART, '\n');
    }
    else {
      uart_write(HOST_UART, (uint8_t *)"................................................................" , EEPROM_MESSAGE_LEN);
      uart_writeb(HOST_UART, '\n');
    }
  }

  return 0;
}

void car_main() {
  FLASH_DATA car_state_ram;
  FLASH_DATA *car_state_flash = (FLASH_DATA *)CAR_STATE_PTR;
  memcpy(&car_state_ram, car_state_flash, FLASH_DATA_SIZE);

  while (1)
  {
    // Step 0: discard bytes from any incorrect messages
    unlock_message_t unlock_msg;
    // This is a blocking read.
    receive_board_message((uint8_t *)&unlock_msg, sizeof(unlock_message_t));
    if (unlock_msg.message_type != MSG_UNLOCK_START)
    {
      continue;
    }

    // Set a delay for 5 seconds.
    prime_delay_timer();
    FI_PROT_VOL((car_unlock() == 0), BAD_BOOL);

    if (fi_vol == true) {
      succ_stall_function(&car_state_ram);
    } else if (fi_vol == false) {
      fail_stall_function(&car_state_ram);
    } else {
      halt_and_catch_fire();
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
  
  // Initialize timers 1 and 0
  FI_PROT_VOL_WEAK((init_timers() == 0), BAD_BOOL);
  if (fi_vol != true) {
    halt_and_catch_fire();
  }

  // Start timer0 for boot timing.
  prime_delay_timer();

  // 0x08000 to 0x10000 - Our firmware (executable, read-only).
  MPURegionSet(0, 0x8000, MPU_RGN_SIZE_32K | MPU_RGN_PERM_EXEC | MPU_RGN_PERM_PRV_RO_USR_NO | MPU_RGN_ENABLE);
  // 0x10000 to 0x20000 - Also our firmware (executable, read-only).
  MPURegionSet(1, 0x10000, MPU_RGN_SIZE_64K | MPU_RGN_PERM_EXEC | MPU_RGN_PERM_PRV_RO_USR_NO | MPU_RGN_ENABLE );
  // 0x20000 to 0x24000 - Flash padding for OTP (no-execute, read-only).
  MPURegionSet(2, 0x20000, MPU_RGN_SIZE_16K | MPU_RGN_PERM_NOEXEC | MPU_RGN_PERM_PRV_RO_USR_NO | MPU_RGN_ENABLE );
  // 0x3FC00 to 0x40000 - Flash space for storing retry attempts (no-execute, read-write).
  MPURegionSet(3, 0x3FC00, MPU_RGN_SIZE_1K | MPU_RGN_PERM_NOEXEC | MPU_RGN_PERM_PRV_RO_USR_NO | MPU_RGN_ENABLE );
  // 0x2000_0000 to 0x2000_8000 - SRAM.
  MPURegionSet(4, 0x20000000, MPU_RGN_SIZE_32K | MPU_RGN_PERM_NOEXEC | MPU_RGN_PERM_PRV_RW_USR_NO | MPU_RGN_ENABLE );
  // 0x4000_0000 to 0x8000_0000 - MMIO peripherals.
  MPURegionSet(5, 0x40000000, MPU_RGN_SIZE_1G | MPU_RGN_PERM_NOEXEC | MPU_RGN_PERM_PRV_RW_USR_NO | MPU_RGN_ENABLE );
  // Enable the MMU.
  MPUEnable(MPU_CONFIG_HARDFLT_NMI);

  // Initialize UART.
  uart_init();
  DEBUG_PRINT("Car started\n");

  // Initialize board link UART.
  setup_board_link();

  SysCtlPeripheralEnable(SYSCTL_PERIPH_EEPROM0);

  FI_PROT_VOL_WEAK((EEPROMInit() == EEPROM_INIT_OK), BAD_BOOL);
  if (fi_vol != true) {
    DEBUG_PRINT("EEPROMInit failed\n");
    halt_and_catch_fire();
    return 1;
  }

  // Initialize thermal ADC.
  // Key into the hash is the first 64 bytes.
  uint32_t eeprom_rng_seed_key[HASH_BLOCK_SIZE_64 / 4];
  EEPROMRead(eeprom_rng_seed_key, EEPROM_RNG_SEED, HASH_BLOCK_SIZE_64);
  // The rest is the random bytes that will be hashed.
  uint32_t eeprom_rng_seed_len = EEPROM_RNG_SEED_SIZE - HASH_BLOCK_SIZE_64;
  uint32_t eeprom_rng_seed[eeprom_rng_seed_len / 4];
  EEPROMRead(eeprom_rng_seed, EEPROM_RNG_SEED + HASH_BLOCK_SIZE_64, eeprom_rng_seed_len);
  // Hash into 64 bytes.
  cc_hash_internal(
    rand_key,
    HASH_BLOCK_SIZE_64,
    (uint8_t *)eeprom_rng_seed,
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

  FLASH_DATA car_state_ram;
  FLASH_DATA *car_state_flash = (FLASH_DATA *)CAR_STATE_PTR;
  memcpy(&car_state_ram, car_state_flash, FLASH_DATA_SIZE);
  RAND_STALL_HALT();
  // Initialize the fail_count to 0 on first boot. (flash is 0xff on first boot).
  if ((car_state_ram.fail_count & 0xff) == 0xff){
    car_state_ram.fail_count = 0;
    saveCarState(&car_state_ram);
  }

  // Wait for one sec delay.
  normal_stall();
  car_main();

  // This is unreachable because car_main never returns.
  halt_and_catch_fire();
}
