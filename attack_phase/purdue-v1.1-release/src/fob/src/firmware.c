/**
 * @file firmware.c
 * @author Purdue eCTF Team
 * @brief Firmware for the fob
 * @date 2023
 *
 * This file contains the firmware for the fob.
 *
 * @copyright Copyright (c) 2023 Purdue eCTF Team
 */

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "inc/hw_flash.h"
#include "inc/hw_memmap.h" 

#include "driverlib/eeprom.h" 
#include "driverlib/flash.h"
#include "driverlib/rom.h" 
#include "driverlib/sysctl.h" 
#include "driverlib/gpio.h" 

#include "eeprom_wrapper.h" 
#include "wrapper.h" 
#include "board_link.h" 
#include "feature_list.h" 

/*** Macro Definitions ***/
#define STATE_PAIRED 1
#define STATE_DEFENSE 2
#define SECRET_SIZE 64
#define PIN_LEN 6

#define DECRYPT_STRING_LEN 48
#define FEATURE_PSSWD_LEN 16
#define FOB_UNLOCK_RESP_LEN 16
#define CAR_ID_LEN 8

/*** Struct and Enum Definitions ***/
/**
 * @struct FEATURE_DATA
 * @brief Structure for feature data
 *
 * @note enabled: each bit represents a feature, 1 if enabled, 0 if disabled
 *       feature_passwords: 16 byte passwords for each feature
 */
typedef struct {
  uint8_t enabled;
  uint8_t feature_passwords[NUM_FEATURES][FOB_KEY_LEN];
} __attribute__((packed)) FEATURE_DATA;

/**
 * @struct ENABLE_PACKET
 * @brief Structure for enable packet
 * @note car_id: 8 byte car id
 *       feature_number: feature number to enable
 *       feature_password: 16 byte password for feature
 */
typedef struct {
  uint8_t car_id[CAR_ID_LEN];
  uint8_t feature_number;
  uint8_t feature_password[FOB_KEY_LEN];
} __attribute__((packed)) ENABLE_PACKET;

/*** Function definitions ***/
void pairFob(MESSAGE_PACKET *init_msg);
void unlockCar();
void enableFeature();
void startCar();
void pair_another_fob(MESSAGE_PACKET *init_msg);
void pair_current_fob(MESSAGE_PACKET *init_msg);
void init_fob();
void sendAckSuccess(void);
void sendAckFailure(void);
uint8_t receiveAck();

/*** Global Variables ***/
uint32_t current_state;

/**
 * @brief The main loop for the fob
 */
int main(void) {
  // Protect Flash from being modified
  for (uint32_t block_start = 0x8000; block_start < 0x23800;
       block_start += FLASH_PROTECT_SIZE) {
    if (FlashProtectSet(block_start, FlashReadOnly)) {
      while (1)
        ;
    }
  }

  // Initialize the EEPROM
  SysCtlPeripheralEnable(SYSCTL_PERIPH_EEPROM0);
  EEPROMInit();

  // Initialize the fob
  init_fob();

  uint8_t previous_sw_state = GPIO_PIN_4;
  uint8_t debounce_sw_state = GPIO_PIN_4;
  uint8_t current_sw_state = GPIO_PIN_4;

  // Main loop
  while (true) {
    // If the fob is in defense mode, sleep for 4 seconds
    if (current_state & STATE_DEFENSE) {
      // sleep for 4 seconds
      ROM_SysCtlDelay(SysCtlClockGet() / 3 * 4);
      current_state &= ~STATE_DEFENSE;
      write_eeprom((uint8_t *)&current_state, FOB_STATE, FOB_STATE_LEN);
    }

    // If there is a message, process it
    if (has_message(HOST_UART)) {

      // Retrieve the message
      MESSAGE_PACKET message;
      memset((void *)&message, 0, sizeof(MESSAGE_PACKET));
      receive_message(HOST_UART, &message);

      // handle the message
      if (message.header == HOST_PAIR_HDR) {
        pairFob(&message);
      } else if (message.header == HOST_FEATURE_HDR) {
        enableFeature(&message);
      }
      memset((void *)&message, 0, sizeof(MESSAGE_PACKET));

      // Clear the UART buffer
      recv_all(HOST_UART);
    }

    // Check if the button is pressed
    current_sw_state = GPIOPinRead(GPIO_PORTF_BASE, GPIO_PIN_4);
    if ((current_sw_state != previous_sw_state) && (current_sw_state == 0)) {
      // debounce the button
      for (int i = 0; i < 10000; i++)
        ;
      debounce_sw_state = GPIOPinRead(GPIO_PORTF_BASE, GPIO_PIN_4);
      if (debounce_sw_state == current_sw_state &&
          current_state & STATE_PAIRED) {
#ifdef CDEBUG
        debug_send_message(HOST_UART, "FOB: Unlocking Car", 18);
#endif
        unlockCar();
#ifdef CDEBUG
        debug_send_message(HOST_UART, "FOB: Waiting for ACK", 20);
#endif
        if (receiveAck()) {
          startCar();
        }
      }
    }
    previous_sw_state = current_sw_state;
  }
}

/**
 * @brief Initializes the fob
 *
 * @note Reads the current state from EEPROM, initializes the UARTs.
 */
void init_fob() {
  // Retrieve the current state from EEPROM
  read_eeprom((uint8_t *)&current_state, FOB_STATE, FOB_STATE_LEN);
#if PAIRED == 1
  current_state |= STATE_PAIRED;
#endif

  // Initialize the UARTs
  setup_comms();

  // Setup SW1
  GPIOPinTypeGPIOInput(GPIO_PORTF_BASE, GPIO_PIN_4);
  GPIOPadConfigSet(GPIO_PORTF_BASE, GPIO_PIN_4, GPIO_STRENGTH_4MA,
                   GPIO_PIN_TYPE_STD_WPU);

#if PAIRED == 1
  GPIOPinWrite(GPIO_PORTF_BASE, GPIO_PIN_1, GPIO_PIN_1); // r
  GPIOPinWrite(GPIO_PORTF_BASE, GPIO_PIN_2, GPIO_PIN_2); // b
  GPIOPinWrite(GPIO_PORTF_BASE, GPIO_PIN_3, GPIO_PIN_3); // g
#else
  if (current_state & STATE_PAIRED) {
    GPIOPinWrite(GPIO_PORTF_BASE, GPIO_PIN_1, GPIO_PIN_1); // r
    GPIOPinWrite(GPIO_PORTF_BASE, GPIO_PIN_2, GPIO_PIN_2); // b
    GPIOPinWrite(GPIO_PORTF_BASE, GPIO_PIN_3, GPIO_PIN_3); // g
  } else {
    GPIOPinWrite(GPIO_PORTF_BASE, GPIO_PIN_1, GPIO_PIN_1); // r
    GPIOPinWrite(GPIO_PORTF_BASE, GPIO_PIN_2, 0);          // b
    GPIOPinWrite(GPIO_PORTF_BASE, GPIO_PIN_3, 0);          // g
  }
#endif
}

/**
 * @brief Handles the pairing of the fob
 *
 * @note If the fob is already paired, it will pair another fob.
 *       If the fob is not paired, it will pair the current fob.
 */
void pairFob(MESSAGE_PACKET *msg) {
  if (current_state & STATE_PAIRED) {
    pair_another_fob(msg);
  } else {
    pair_current_fob(msg);
  }
}

/**
 * @brief Pairs another fob
 *
 * @note This function is called when the fob is already paired.
 */
void pair_another_fob(MESSAGE_PACKET *init_msg) {
  if (init_msg->message_len != PIN_LEN) {
    sendAckFailure();
    return;
  }

  // Calculate the hash of received pin
  uint8_t pin_hash[FOB_PIN_HASH_LEN];
  memset((void *)pin_hash, 0, FOB_PIN_HASH_LEN);

  uint8_t salted_pin[FOB_PIN_HASH_LEN];
  read_eeprom(salted_pin, FOB_SECRET_SALT, FOB_SECRET_SALT_LEN);
  memcpy(salted_pin + FOB_SECRET_SALT_LEN, init_msg->buffer, PIN_LEN);

  hash_string(pin_hash, salted_pin, SECRET_SIZE/2);
  memset((void *)salted_pin, 0, FOB_PIN_HASH_LEN);

  // Fetch stored hash from EEPROM
  uint8_t stored_pin_hash[FOB_PIN_HASH_LEN];
  memset((void *)stored_pin_hash, 0, FOB_PIN_HASH_LEN);
  read_eeprom(stored_pin_hash, FOB_PIN_HASH, FOB_PIN_HASH_LEN);

  if (memcmp(pin_hash, stored_pin_hash, FOB_PIN_HASH_LEN) == 0) {
    // if the pin matches
    sendAckSuccess();

    // Prepare the message to send to the unpaired fob
    MESSAGE_PACKET message;
    memset((void *)&message, 0, sizeof(MESSAGE_PACKET));
    message.header = BOARD_PAIR_HDR;
    // Put the key in the message
    read_eeprom(message.buffer, FOB_KEY, FOB_KEY_LEN);
    message.message_len = FOB_KEY_LEN;
    // Put the hash in the message
    read_eeprom(message.buffer + message.message_len, FOB_PIN_HASH,
                FOB_PIN_HASH_LEN);
    message.message_len += FOB_PIN_HASH_LEN;
    // Put the salt in the message
    read_eeprom(message.buffer + message.message_len, FOB_SECRET_SALT,
                FOB_SECRET_SALT_LEN);
    message.message_len += FOB_SECRET_SALT_LEN;
    send_message(BOARD_UART, &message);

    // clean up the message and pin hash
    memset((void *)&message, 0, sizeof(MESSAGE_PACKET));
    memset((void *)stored_pin_hash, 0, FOB_PIN_HASH_LEN);

    GPIOPinWrite(GPIO_PORTF_BASE, GPIO_PIN_1, 0);          // r
    GPIOPinWrite(GPIO_PORTF_BASE, GPIO_PIN_2, 0);          // b
    GPIOPinWrite(GPIO_PORTF_BASE, GPIO_PIN_3, GPIO_PIN_3); // g
  } else {
    // if the pin does not match
    memset((void *)stored_pin_hash, 0, FOB_PIN_HASH_LEN);

#ifdef CDEBUG
    debug_send_message(HOST_UART, "Hash not correct", 16);
#endif

    sendAckFailure();

    // enter defense mode
    current_state |= STATE_DEFENSE;
    write_eeprom((uint8_t *)&current_state, FOB_STATE, FOB_STATE_LEN);
  }

  // clean up the pin hashes
  memset((void *)pin_hash, 0, FOB_PIN_HASH_LEN);
  memset((void *)stored_pin_hash, 0, FOB_PIN_HASH_LEN);
}

/**
 * @brief Pairs the current fob
 * @note This function is called when the fob is not paired.
 */
void pair_current_fob(MESSAGE_PACKET *init_msg) {
  // Retrieve the message
  MESSAGE_PACKET message;
  memset((void *)&message, 0, sizeof(MESSAGE_PACKET));
  receive_message(BOARD_UART, &message);

  if (message.header != BOARD_PAIR_HDR ||
      message.message_len !=
          FOB_KEY_LEN + FOB_PIN_HASH_LEN + FOB_SECRET_SALT_LEN) {
    sendAckFailure();
    return;
  }

  sendAckSuccess();
  current_state |= STATE_PAIRED;

  // Store the key, pin hash, and salt in EEPROM
  write_eeprom((uint8_t *)&current_state, FOB_STATE, FOB_STATE_LEN);
  write_eeprom(message.buffer, FOB_KEY, FOB_KEY_LEN);
  write_eeprom(message.buffer + FOB_KEY_LEN, FOB_PIN_HASH, FOB_PIN_HASH_LEN);
  write_eeprom(message.buffer + FOB_KEY_LEN + FOB_PIN_HASH_LEN, FOB_SECRET_SALT,
               FOB_SECRET_SALT_LEN);

  // clean up the message
  memset((void *)&message, 0, sizeof(MESSAGE_PACKET));

  GPIOPinWrite(GPIO_PORTF_BASE, GPIO_PIN_1, GPIO_PIN_1); // r
  GPIOPinWrite(GPIO_PORTF_BASE, GPIO_PIN_2, GPIO_PIN_2); // b
  GPIOPinWrite(GPIO_PORTF_BASE, GPIO_PIN_3, GPIO_PIN_3); // g
}

/**
 * @brief Enables a feature based on the message
 *
 * @param enable_message The message containing the enable packet
 */
void enableFeature(MESSAGE_PACKET *enable_message) {
  if (!(current_state & STATE_PAIRED)) {
#ifdef CDEBUG
    debug_send_message(HOST_UART, "Fob is not paired\n", 17);
#endif
    sendAckFailure();
    return;
  }
  if (enable_message->message_len != sizeof(ENABLE_PACKET)) {
#ifdef CDEBUG
    debug_send_message(HOST_UART, "Failed to enable feature\n", 25);
#endif
    sendAckFailure();
    return;
  }

#ifdef CDEBUG
  debug_send_message(HOST_UART, "Enabling feature\n", 17);
#endif

  // Retrieve the packet
  ENABLE_PACKET *enable_packet = (ENABLE_PACKET *)(enable_message->buffer);

  if (enable_packet->feature_number > NUM_FEATURES ||
      enable_packet->feature_number <= 0) {
#ifdef CDEBUG
    debug_send_message(HOST_UART, "Invalid feature number\n", 23);
#endif
    sendAckFailure();
    return;
  }

  // read the feature data
  FEATURE_DATA fob_feature_data;
  memset((void *)&fob_feature_data, 0, sizeof(FEATURE_DATA));
  read_eeprom((uint8_t *)&fob_feature_data, FOB_FEATURE_DATA,
              FOB_FEATURE_DATA_LEN);

  if (fob_feature_data.enabled & (1 << (enable_packet->feature_number - 1))) {
    // Feature is already enabled
#ifdef CDEBUG
    debug_send_message(HOST_UART, "Feature already enabled\n", 24);
#endif
    sendAckFailure();
    return;
  }

  // Store the feature password
  memcpy(fob_feature_data.feature_passwords[enable_packet->feature_number - 1],
         enable_packet->feature_password, FOB_KEY_LEN);
  fob_feature_data.enabled |= (1 << (enable_packet->feature_number - 1));

  write_eeprom((uint8_t *)&fob_feature_data, FOB_FEATURE_DATA,
               FOB_FEATURE_DATA_LEN);
  memset((void *)&fob_feature_data, 0, sizeof(FEATURE_DATA));

  sendAckSuccess();
#ifdef CDEBUG
  debug_send_message(HOST_UART, "FOB: Feature enabled\n", 21);
#endif
  return;
}

/**
 * @brief Unlocks the car
 *
 * @note This function is called when the button is pressed
 */
void unlockCar() {
  // Prepare the message
  MESSAGE_PACKET message;
  memset((void *)&message, 0, sizeof(MESSAGE_PACKET));
  message.header = UNLOCK_HDR;
  send_message(BOARD_UART, &message);
  memset((void *)&message, 0, sizeof(MESSAGE_PACKET));

#ifdef CDEBUG
  debug_send_message(HOST_UART, "FOB: Sent unlock message to board", 33);
#endif

  // Retrieve the challenge
  receive_message(BOARD_UART, &message);
  if (message.header != CHALLENGE_HDR) {
    return;
  }

  if (message.message_len != (FOB_FEATURE_DATA_LEN - 1)) {
    return;
  }

#ifdef CDEBUG
  debug_send_message(HOST_UART, "FOB RCHAL:", 10);
  debug_send_int(HOST_UART, message.message_len);
  debug_send_message(HOST_UART, "bs", 2);
  for (int i = 0; i < 16; i++) {
    debug_send_int(HOST_UART, message.buffer[i]);
    debug_send_message(HOST_UART, ",", 1);
  }
  debug_send_message(HOST_UART, "\n", 1);
#endif

  // Prepare the response
  MESSAGE_PACKET response_msg;
  memset((void *)&response_msg, 0, sizeof(MESSAGE_PACKET));
  response_msg.header = UNLOCK_RES_HDR;

  uint8_t key[FOB_KEY_LEN];
  memset((void *)key, 0, FOB_KEY_LEN);
  read_eeprom(key, FOB_KEY, FOB_KEY_LEN);

#ifdef CDEBUG
  debug_send_message(HOST_UART, "FOB KEY:", 8);
  for (int i = 0; i < 16; i++) {
    debug_send_int(HOST_UART, key[i]);
    debug_send_message(HOST_UART, ",", 1);
  }
  debug_send_message(HOST_UART, "\n", 1);
#endif

  // Send the response message
  uint8_t cbuf[DECRYPT_STRING_LEN] = {0};
  memcpy(cbuf, message.buffer, DECRYPT_STRING_LEN);
  uint8_t mbuf[FOB_UNLOCK_RESP_LEN] = {0};
  if (decrypt_string(mbuf, cbuf, message.message_len, key) == FOB_UNLOCK_RESP_LEN) {
    memcpy(response_msg.buffer, mbuf, FOB_KEY_LEN);
    response_msg.message_len = FOB_KEY_LEN;
  } else {
    response_msg.message_len = 0;
  }

  memset((void *)key, 0, FOB_KEY_LEN);
  send_message(BOARD_UART, &response_msg);
  memset((void *)&message, 0, sizeof(MESSAGE_PACKET));
  memset((void *)&response_msg, 0, sizeof(MESSAGE_PACKET));

#ifdef CDEBUG
  debug_send_message(HOST_UART, "FOB DECR:", 9);
  debug_send_int(HOST_UART, response_msg.message_len);
  debug_send_message(HOST_UART, "bs", 2);
  for (int i = 0; i < 16; i++) {
    debug_send_int(HOST_UART, response_msg.buffer[i]);
    debug_send_message(HOST_UART, ",", 1);
  }
  debug_send_message(HOST_UART, "\n", 1);
#endif
}

/**
 * @brief Starts the car after the car is unlocked
 */
void startCar() {
  MESSAGE_PACKET message;
  memset((void *)&message, 0, sizeof(MESSAGE_PACKET));
  message.header = START_HDR;
  message.message_len = FOB_FEATURE_DATA_LEN;
  read_eeprom(message.buffer, FOB_FEATURE_DATA, FOB_FEATURE_DATA_LEN);

  send_message(BOARD_UART, &message);
  memset((void *)&message, 0, sizeof(MESSAGE_PACKET));
#ifdef CDEBUG
  debug_send_message(HOST_UART, "FOB: Sent start message to board", 32);
#endif
}

/**
 * @brief Function to receive ACK message
 *
 * @return uint8_t 0 if ACK is not received, 1 if ACK is received
 */
uint8_t receiveAck() {
  MESSAGE_PACKET message;
  memset((void *)&message, 0, sizeof(MESSAGE_PACKET));

  receive_message(BOARD_UART, &message);
  if (message.header != ACK_HDR || message.message_len != 1) {
    return 0;
  }
  return message.buffer[0];
}

/**
 * @brief Sends successful ACK message
 */
void sendAckSuccess(void) {
  // Create packet for successful ack and send
  MESSAGE_PACKET message;
  memset((void *)&message, 0, sizeof(MESSAGE_PACKET));

  message.header = ACK_HDR;
  message.buffer[0] = ACK_SUCCESS;
  message.message_len = 1;

  send_message(HOST_UART, &message);
  memset((void *)&message, 0, sizeof(MESSAGE_PACKET));
}

/**
 * @brief Sends unsuccessful ACK message
 */
void sendAckFailure(void) {
  // Create packet for unsuccessful ack and send
  MESSAGE_PACKET message;
  memset((void *)&message, 0, sizeof(MESSAGE_PACKET));

  message.header = ACK_HDR;
  message.buffer[0] = ACK_FAIL;
  message.message_len = 1;

  send_message(HOST_UART, &message);
  memset((void *)&message, 0, sizeof(MESSAGE_PACKET));
}
