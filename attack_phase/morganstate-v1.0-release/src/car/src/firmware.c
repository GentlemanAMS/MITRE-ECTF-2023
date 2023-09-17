/**
 * @file main.c
 * @author Frederich Stine
 * @brief eCTF Car Example Design Implementation
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
#include <stdio.h>
#include <unistd.h>

#include "inc/hw_ints.h"
#include "inc/hw_memmap.h"

#include "driverlib/eeprom.h"
#include "driverlib/gpio.h"
#include "driverlib/interrupt.h"
#include "driverlib/pin_map.h"
#include "driverlib/sysctl.h"
#include "driverlib/timer.h"
#include "driverlib/flash.h"

#include "secrets.h"

#include "board_link.h"
#include "feature_list.h"
#include "uart.h"

#include "aead.h"
#include "api.h"
#define MAX_MESSAGE_LENGTH			    16
#define MAX_ASSOCIATED_DATA_LENGTH	16

#include "simplerandom.h"

/*** Structure definitions ***/
// Structure of start_car packet FEATURE_DATA
typedef struct {
  uint8_t car_id[8];
  uint8_t num_active;
  uint8_t features[NUM_FEATURES];
  uint8_t Hash[NUM_FEATURES][32];
} FEATURE_DATA;

typedef struct
{
  SimpleRandomCong_t rng_cong;
  uint8_t paired;
} FLASH_DATA;

/*** Macro Definitions ***/
// Definitions for unlock message location in EEPROM
#define UNLOCK_EEPROM_LOC 0x7C0
#define UNLOCK_EEPROM_SIZE 64

/*** Function definitions ***/
// Core functions - unlockCar and startCar
void unlockCar(FLASH_DATA *car_state_ram);
//void unlockCar(void);
void startCar(void);
void saveCarState(FLASH_DATA *flash_data);

// Helper functions - sending ack messages
void sendAckSuccess(void);
void sendAckFailure(void);

int memcmp_new(const uint8_t *__s1, const uint8_t *__s2, int n);
void B16_RNG (uint8_t b[16], FLASH_DATA *car_state_ram);

// Declare password
const uint8_t pass[16] = PASSWORD;
const uint8_t car_id[8] = CAR_ID;
const uint8_t auth[16] = AUTHENTICATON;
const uint8_t key[16] = KEY;

#define CAR_STATE_PTR 0x3F600
#define FLASH_DATA_SIZE         \
  (sizeof(FLASH_DATA) % 4 == 0) \
      ? sizeof(FLASH_DATA)      \
      : sizeof(FLASH_DATA) + (4 - (sizeof(FLASH_DATA) % 4))
#define FLASH_PAIRED 0x00
#define FLASH_UNPAIRED 0xFF

/**
 * @brief Main function for the car example
 *
 * Initializes the RF module and waits for a successful unlock attempt.
 * If successful prints out the unlock flag.
 */
int main(void) {

  FLASH_DATA car_state_ram;
  FLASH_DATA *car_state_flash = (FLASH_DATA *)CAR_STATE_PTR;

  if (car_state_flash->paired == FLASH_UNPAIRED){
    simplerandom_cong_seed(&car_state_ram.rng_cong, 1234567890u);
    car_state_ram.paired = FLASH_PAIRED;
    saveCarState(&car_state_ram);
  }

  if (car_state_flash->paired == FLASH_PAIRED)
  {
    memcpy(&car_state_ram, car_state_flash, FLASH_DATA_SIZE);
  }
  //uint8_t data[16];

  // Ensure EEPROM peripheral is enabled
  SysCtlPeripheralEnable(SYSCTL_PERIPH_EEPROM0);
  EEPROMInit();

  // Initialize UART peripheral
  uart_init();

  // Initialize board link UART
  setup_board_link();

  while (true) {

    unlockCar(&car_state_ram);
    //unlockCar();
  }
}

/**
 * @brief Function that handles unlocking of car
 */

/*
void unlockCar(void) {
  // Create a message struct variable for receiving data
  MESSAGE_PACKET message;
  uint8_t buffer[256];
  message.buffer = buffer;

  // Receive packet with some error checking
  receive_board_message_by_type(&message, UNLOCK_MAGIC);

  // Pad payload to a string
  message.buffer[message.message_len] = 0;

  // If the data transfer is the password, unlock
  if (!strcmp((char *)(message.buffer), (char *)pass)) {
    uint8_t eeprom_message[64];
    // Read last 64B of EEPROM
    EEPROMRead((uint32_t *)eeprom_message, UNLOCK_EEPROM_LOC,
               UNLOCK_EEPROM_SIZE);

    // Write out full flag if applicable
    uart_write(HOST_UART, eeprom_message, UNLOCK_EEPROM_SIZE);

    sendAckSuccess();

    startCar();
  } else {
    sendAckFailure();
  }
}
*/

void unlockCar(FLASH_DATA *car_state_ram) {
  unsigned char       msg[MAX_MESSAGE_LENGTH];
  unsigned char		nonce[CRYPTO_NPUBBYTES];
  unsigned long long  mlen;

  // Create a message struct variable for receiving data
  MESSAGE_PACKET message;

  uint8_t buffer[256];
  message.buffer = buffer;

  receive_board_message_by_type(&message, AUTH_MAGIC);

  if (!memcmp_new((message.buffer), auth, 16)) {
    message.message_len = 16;
    message.magic = NONCE_MAGIC;
    message.buffer = (uint8_t*)nonce;

    B16_RNG (nonce, car_state_ram);

    send_board_message(&message);
    
    MESSAGE_PACKET message2;
    message2.buffer = buffer;

    // Receive packet with some error checking
    receive_board_message_by_type(&message2, UNLOCK_MAGIC);
    
    crypto_aead_decrypt(msg, &mlen, NULL, message2.buffer, MAX_MESSAGE_LENGTH + CRYPTO_ABYTES, NULL, MAX_ASSOCIATED_DATA_LENGTH, nonce, key);
    
    // If the data transfer is the password, unlock
    if (memcmp_new(msg, pass, 16) == 0) {
      uint8_t eeprom_message[64];
      // Read last 64B of EEPROM
      EEPROMRead((uint32_t *)eeprom_message, UNLOCK_EEPROM_LOC, UNLOCK_EEPROM_SIZE);
      //int j = 0;
      //while(j == 0){
      //  if((uint8_t)uart_readb(HOST_UART) == 'n'){
      //    j = 1;
      //  }
      //}

      // Write out full flag if applicable
      uart_write(HOST_UART, eeprom_message, UNLOCK_EEPROM_SIZE);

      sendAckSuccess();
      //send_board_message(&message);

      startCar();
    } else {
      //uart_write(HOST_UART, "FAIL", (uint32_t)8);
      sendAckFailure();
    }
  }
}

/**
 * @brief Function that handles starting of car - feature list
 */
void startCar(void) {
  // Create a message struct variable for receiving data
  MESSAGE_PACKET message;
  uint8_t buffer[256];
  message.buffer = buffer;

  // Receive start message
  receive_board_message_by_type(&message, START_MAGIC);

  FEATURE_DATA *feature_info = (FEATURE_DATA *)buffer;

  // Verify correct car id
  if (memcmp_new(car_id, feature_info->car_id, 8)) {
    return;
  }
  //uart_write(HOST_UART, (uint8_t*)"here", 5);
  // Print out features for all active features
  
  for (int i = 0; i < feature_info->num_active; i++) {
    uint8_t eeprom_message[64];

    uint32_t offset = feature_info->features[i] * FEATURE_SIZE;

    if (offset > FEATURE_END) {
        offset = FEATURE_END;
    }
    
    EEPROMRead((uint32_t *)eeprom_message, FEATURE_END - offset, FEATURE_SIZE);

    uart_write(HOST_UART, eeprom_message, FEATURE_SIZE);
  }
}

/**
 * @brief Function to send successful ACK message
 */
void sendAckSuccess(void) {
  // Create packet for successful ack and send
  MESSAGE_PACKET message;

  uint8_t buffer[1];
  message.buffer = buffer;
  message.magic = ACK_MAGIC;
  buffer[0] = ACK_SUCCESS;
  message.message_len = 1;

  send_board_message(&message);
}

/**
 * @brief Function to send unsuccessful ACK message
 */
void sendAckFailure(void) {
  // Create packet for unsuccessful ack and send
  MESSAGE_PACKET message;

  uint8_t buffer[1];
  message.buffer = buffer;
  message.magic = ACK_MAGIC;
  buffer[0] = ACK_FAIL;
  message.message_len = 1;

  send_board_message(&message);
}

int memcmp_new(const uint8_t *__s1, const uint8_t *__s2, int n) {
  int i;
  int a = 0;
  for (i = 0; i < n; i++) {
    if (__s1[i] == __s2[i]) {
      a = a || 0;
    }
    else {
      a = a || 1;
    }
  }
  return a;
}

void saveCarState(FLASH_DATA *flash_data)
{
  // Save the FLASH_DATA to flash memory
  FlashErase(CAR_STATE_PTR);
  FlashProgram((uint32_t *)flash_data, CAR_STATE_PTR, FLASH_DATA_SIZE);
}

void B16_RNG (uint8_t b[16], FLASH_DATA *car_state_ram){
    
  uint32_t rng_value;
  int i;

  for(i = 0; i < 4; i++){
    rng_value = simplerandom_cong_next(&car_state_ram->rng_cong);

    b[4 * i + 3] = (uint8_t)rng_value;
    b[4 * i + 2] = (uint8_t)(rng_value>>=8);
    b[4 * i + 1] = (uint8_t)(rng_value>>=8);
    b[4 * i] = (uint8_t)(rng_value>>=8);
  }

  saveCarState(car_state_ram);
}