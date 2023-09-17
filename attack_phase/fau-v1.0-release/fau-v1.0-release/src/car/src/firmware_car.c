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
#include "inc/hw_sysctl.h"
#include "inc/hw_nvic.h"
#include "inc/hw_memmap.h"
#include "inc/hw_types.h"

#include "driverlib/adc.h"
#include "driverlib/eeprom.h"
#include "driverlib/flash.h"
#include "driverlib/gpio.h"
#include "driverlib/interrupt.h"
#include "driverlib/pin_map.h"
#include "driverlib/sysctl.h"
#include "driverlib/timer.h"
#include "driverlib/debug.h"

#include "secrets.h"

#include "firmware.h"
#include "board_link.h"
#include "feature_list.h"
#include "uart.h"
#include "secure.h"
#include "aes.h"

#undef NUM_INTERRUPTS
#define NUM_INTERRUPTS                          155

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
  SysCtlPeripheralEnable(SYSCTL_PERIPH_EEPROM0);
  EEPROMInit();

  // Change LED color: red
  GPIOPinWrite(GPIO_PORTF_BASE, GPIO_PIN_1, GPIO_PIN_1); // r
  GPIOPinWrite(GPIO_PORTF_BASE, GPIO_PIN_2, 0); // b
  GPIOPinWrite(GPIO_PORTF_BASE, GPIO_PIN_3, 0); // g

  // Initialize UART peripheral
  uart_init();

  // Initialize board link UART
  setup_board_link();

  while (true) {

    unlockCar();
  }
}

/**
 * @brief Function that handles unlocking of car
 */
void unlockCar(void) {
  uint8_t session_key[16] = {0};
  uint8_t eeprom_message[UNLOCK_EEPROM_SIZE] = {0};

  aes_sharedkey_rx(session_key);
  bool pass_valid = aes_unlock_car(pass, 6, session_key);  

  if(pass_valid) {
    // Read last 64B of EEPROM
    EEPROMRead((uint32_t *)eeprom_message, UNLOCK_EEPROM_LOC,
               UNLOCK_EEPROM_SIZE);

    // Write out unlock message
    volatile uint32_t br = uart_write(HOST_UART, eeprom_message, UNLOCK_EEPROM_SIZE);
    
    sendAckSuccess();

    startCar();
  } else {
    sendAckFailure();
  }

}

/**
 * @brief Function that handles starting of car - feature list
 */
void startCar(void) {
  uint8_t session_key[16] = {0};

  aes_sharedkey_rx(session_key);
  bool pass_valid = aes_unlock_car(pass, 6, session_key);  

  if(pass_valid) {
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
      uint8_t eeprom_message[64];

      uint32_t offset = feature_info->features[i] * FEATURE_SIZE;


      // TODO: Verify if this is causing an issue. 
      if (offset > FEATURE_END) {
          offset = FEATURE_END;
      }

      EEPROMRead((uint32_t *)eeprom_message, FEATURE_END - offset, FEATURE_SIZE);

      uart_write(HOST_UART, eeprom_message, FEATURE_SIZE);
    }

    // Change LED color: green
    GPIOPinWrite(GPIO_PORTF_BASE, GPIO_PIN_1, 0); // r
    GPIOPinWrite(GPIO_PORTF_BASE, GPIO_PIN_2, 0); // b
    GPIOPinWrite(GPIO_PORTF_BASE, GPIO_PIN_3, GPIO_PIN_3); // g
  } else {
    return;
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