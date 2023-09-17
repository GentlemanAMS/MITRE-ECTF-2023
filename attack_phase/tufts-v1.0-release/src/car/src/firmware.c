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

#include "inc/hw_ints.h"
#include "inc/hw_memmap.h"

#include "driverlib/eeprom.h"
#include "driverlib/gpio.h"
#include "driverlib/interrupt.h"
#include "driverlib/pin_map.h"
#include "driverlib/sysctl.h"
#include "driverlib/timer.h"

#include "isaac.h"
#include "aes.h"

#include "secrets.h"

#include "board_link.h"
#include "feature_list.h"
#include "uart.h"
#include "car_rand.h"
#include "feature_validation.h"


/*** Structure definitions ***/
// Structure of start_car packet FEATURE_DATA
typedef struct {
  uint8_t car_id[8];
  uint8_t num_active;
  uint8_t  blob[NUM_FEATURES][16];
} FEATURE_DATA;

/*** Macro Definitions ***/
// Definitions for unlock message location in EEPROM
#define UNLOCK_EEPROM_LOC 0x7C0
#define UNLOCK_EEPROM_SIZE 64
#define AES_BLOCKSIZE 16


/*** Function definitions ***/
// Core functions - unlockCar and startCar
void unlockCar(const uint8_t *key);
void startCar(void);

// Helper functions - sending ack messages
void sendAckSuccess(void);
void sendAckFailure(void);

// Declare password
const uint8_t pass[] = PASSWORD;
const uint8_t car_id[] = CAR_ID;

/**
 * @brief Main function for the car example
 *
 * Initializes the RF module and waits for a successful unlock attempt.
 * If successful prints out the unlock flag.
 */
int main(void) {
  // Ensure EEPROM peripheral is enabled
  SysCtlPeripheralEnable(SYSCTL_PERIPH_EEPROM0);
  EEPROMInit();

  // Initialize UART peripheral
  uart_init();

  // Initialize board link UART
  setup_board_link();

  // Enable the Timer peripherals
  SysCtlPeripheralEnable(SYSCTL_PERIPH_TIMER0);
  SysCtlPeripheralEnable(SYSCTL_PERIPH_TIMER1);
  // Wait for the Timer modules to be ready.
  while(!SysCtlPeripheralReady(SYSCTL_PERIPH_TIMER0));
  while(!SysCtlPeripheralReady(SYSCTL_PERIPH_TIMER1));
  TimerConfigure(TIMER0_BASE, TIMER_CFG_PERIODIC);
  // Not sure PIOSC timer configuration works on this part
  TimerClockSourceSet(TIMER0_BASE, TIMER_CLOCK_PIOSC);
  TimerEnable(TIMER0_BASE, TIMER_A);
  TimerConfigure(TIMER1_BASE, TIMER_CFG_PERIODIC);
  TimerClockSourceSet(TIMER1_BASE, TIMER_CLOCK_SYSTEM);
  TimerEnable(TIMER1_BASE, TIMER_A);

  while (true) {

    unlockCar(pass);
  }
}

/**
 * @brief Function that handles unlocking of car
 */
void unlockCar(const uint8_t *key) {
  static bool rng_seeded = false;
  static bool requested = false;
  static uint32_t challenge[AES_BLOCKSIZE / 4];

  // Receive packet with some error checking, then copy over
  MESSAGE_PACKET message;
  uint8_t buffer[256];
  message.buffer = buffer;
  
  receive_board_message(&message);

  // Check whether message is REQUEST or UNLOCK
  if (message.magic == REQUEST_MAGIC) {
    if (!rng_seeded) {
      // Do this on first challenge generation to incorporate timing randomness
      seed_rng();
      rng_seeded = true;
    }
    // Create a message struct variable
    MESSAGE_PACKET challenge_message;
    challenge_message.message_len = AES_BLOCKSIZE;
    challenge_message.magic = UNLOCK_MAGIC;
    challenge_message.buffer = challenge;
    
    // Car creates challenge for fob to complete
    for (int i = 0; i < 4; i++) {
      challenge[i] = rand();      
    }

    // Note that fob requested challenge (for later verification)
    requested = true;

    // Car sends challenge to fob
    send_board_message(&challenge_message);
  } 

  else if (message.magic == UNLOCK_MAGIC) {
    // Check that we're handling legitimate unlock request
    if (!requested) {
      sendAckFailure();
      return;       
    }

    // Now we can assume request is valid, so revert back
    requested = false;

    static uint8_t challenge_int8[AES_BLOCKSIZE]; 
    memcpy(challenge_int8, &challenge, sizeof(challenge));

    // Receive encrypted challenge from fob
    uint8_t encrypted_challenge[AES_BLOCKSIZE];
    memcpy(encrypted_challenge, message.buffer, AES_BLOCKSIZE);

    // Decrypt challenge from fob & verify match
    struct AES_ctx aes_ctx;
    AES_init_ctx(&aes_ctx, key);
    AES_ECB_decrypt(&aes_ctx, encrypted_challenge);

    for (int i = 0; i < AES_BLOCKSIZE; i++) {
        if (challenge_int8[i] != encrypted_challenge[i]) {
          // Challenges don't match, so don't unlock
          sendAckFailure(); 
          return;
        }              
    }

    // Assumed challenges match, so unlock car
    uint8_t eeprom_message[64];
    // Read last 64B of EEPROM
    EEPROMRead((uint32_t *)eeprom_message, UNLOCK_EEPROM_LOC,
               UNLOCK_EEPROM_SIZE);

    // Write out full flag if applicable
    uart_write(HOST_UART, eeprom_message, UNLOCK_EEPROM_SIZE);

    sendAckSuccess();
    startCar();
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
  if (strcmp((char *)car_id, (char *)feature_info->car_id)) {
    return;
  }

  // Print out features for all active features
  for (int i = 0; i < feature_info->num_active; i++) {
    struct validate_result v_feature = validate_feature(feature_info->blob[i]);

    if (v_feature.valid == false)
    {
      // Change LED color: red
      // Disabled so as to not make our attacker's lives easier
      // GPIOPinWrite(GPIO_PORTF_BASE, GPIO_PIN_1, GPIO_PIN_1); // r
      // GPIOPinWrite(GPIO_PORTF_BASE, GPIO_PIN_2, 0); // b
      // GPIOPinWrite(GPIO_PORTF_BASE, GPIO_PIN_3, 0); // g
      // SysCtlDelay(SysCtlClockGet() / 12); // delay 0.25 seconds
      // Change LED color: green
      // GPIOPinWrite(GPIO_PORTF_BASE, GPIO_PIN_1, 0); // r
      // GPIOPinWrite(GPIO_PORTF_BASE, GPIO_PIN_2, 0); // b
      // GPIOPinWrite(GPIO_PORTF_BASE, GPIO_PIN_3, GPIO_PIN_3); // g
      // SysCtlDelay(SysCtlClockGet() / 12); // delay 0.25 seconds
      continue;
    }

    uint8_t eeprom_message[64];

    uint32_t offset = v_feature.feat_num * FEATURE_SIZE;

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