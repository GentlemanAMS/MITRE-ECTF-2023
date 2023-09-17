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

#include "secrets.h"

#include "board_link.h"
#include "feature_list.h"
#include "constant.h"
#include "uart.h"
#include "monocypher.h"
#include "entropy.h"

/*** Structure definitions ***/
// Structure of start_car packet FEATURE_DATA
typedef struct FEATURE_DATA {
    uint8_t car_id;
    uint8_t num_active;
    uint8_t features[NUM_FEATURES];
    uint8_t signatures[NUM_FEATURES][SIGNATURE_LEN];
} FEATURE_DATA;

// Defines a struct for challenge-response authentication
typedef struct {
    uint8_t nonce[NONCE_LEN];
    uint8_t mac[MAC_LEN];
    uint8_t challenge[KEY_LEN + 6];
} UNLOCK_PACKET;

/*** Macro Definitions ***/
// Definitions for unlock message location in EEPROM
#define UNLOCK_EEPROM_LOC 0x7C0
#define UNLOCK_EEPROM_SIZE 64

/*** Function definitions ***/
// Core functions - unlockCar and startCar
void unlockCar(void);
void startCar(void);

// Helper functions - sending ack messages
uint8_t receiveAck();
void sendAckSuccess(void);
void sendAckFailure(void);

// Declare password
const uint8_t unlock_cmd[] = "Unlock";
const uint8_t car_id = (uint8_t)CAR_ID[0];

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

    // Change LED color: red
    GPIOPinWrite(GPIO_PORTF_BASE, GPIO_PIN_1, GPIO_PIN_1);  // r
    GPIOPinWrite(GPIO_PORTF_BASE, GPIO_PIN_2, 0);           // b
    GPIOPinWrite(GPIO_PORTF_BASE, GPIO_PIN_3, 0);           // g

    // Initialise the RNG
    entropy_init();

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
    // Create a message struct variable for receiving data
    MESSAGE_PACKET message;
    uint8_t buffer[256];
    message.buffer = buffer;

    // Receive packet with some error checking
    receive_board_message_by_type(&message, UNLOCK_MAGIC, 7);
    message.buffer[6] = 0;

    // If the data transfer is not the password, return
    if (strcmp((char *)(message.buffer), (char *)unlock_cmd)) {
        sendAckFailure();
        return;
    }

    sendAckSuccess();

    uint8_t challenge[KEY_LEN];
    uint8_t nonce[NONCE_LEN];
    uint8_t mac[MAC_LEN];
    get_random_bytes(challenge, KEY_LEN);
    get_random_bytes(nonce, NONCE_LEN);

    UNLOCK_PACKET *unlock_packet = (UNLOCK_PACKET *)buffer;
    crypto_lock(mac, unlock_packet->challenge, (uint8_t *)CAR_SECRET, nonce,
                challenge, KEY_LEN);
    memcpy(unlock_packet->nonce, nonce, NONCE_LEN);
    memcpy(unlock_packet->mac, mac, MAC_LEN);

    // Send challenge
    message.magic = CHALLENGE_MAGIC;
    message.message_len = sizeof(UNLOCK_PACKET);
    send_board_message(&message);

    if (!receiveAck()) {
        return;
    }

    // Receive response
    receive_board_message_by_type(&message, CHALLENGE_MAGIC,
                                  sizeof(UNLOCK_PACKET));

    uint8_t response[KEY_LEN + 6];
    if (crypto_unlock(response, (uint8_t *)CAR_SECRET, unlock_packet->nonce,
                      unlock_packet->mac, unlock_packet->challenge,
                      KEY_LEN + 6)) {
        crypto_wipe(unlock_packet, sizeof(UNLOCK_PACKET));
        sendAckFailure();
        return;
    }

    if (memcmp((void *)response, (void *)"Unlock", 6) ||
        crypto_verify32(response + 6, challenge)) {
        crypto_wipe(unlock_packet, sizeof(UNLOCK_PACKET));
        sendAckFailure();
        return;
    }

    uint8_t eeprom_message[64];
    // Read last 64B of EEPROM
    EEPROMRead((uint32_t *)eeprom_message, UNLOCK_EEPROM_LOC,
               UNLOCK_EEPROM_SIZE);

    // Write out full flag if applicable
    uart_write(HOST_UART, eeprom_message, UNLOCK_EEPROM_SIZE);

    sendAckSuccess();

    startCar();
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
    receive_board_message_by_type(&message, START_MAGIC, 256);

    FEATURE_DATA *feature_info = (FEATURE_DATA *)buffer;

    // Verify correct car id
    if (car_id != feature_info->car_id) {
        return;
    }

    // Verify all the signatures
    for (int i = 0; i < feature_info->num_active; i++) {
        uint8_t feature_buffer[2] = {feature_info->car_id,
                                     feature_info->features[i]};
        if (crypto_check(feature_info->signatures[i], (uint8_t *)CA_PK,
                         feature_buffer, 2)) {
            // Wrong signature, might be an attack
            return;
        }
    }

    // Print out features for all active features
    for (int i = 0; i < feature_info->num_active; i++) {
        uint8_t eeprom_message[64];

        uint32_t offset = feature_info->features[i] * FEATURE_SIZE;

        if (offset > FEATURE_END) {
            offset = FEATURE_END;
        }

        EEPROMRead((uint32_t *)eeprom_message, FEATURE_END - offset,
                   FEATURE_SIZE);

        uart_write(HOST_UART, eeprom_message, FEATURE_SIZE);
    }

    // Change LED color: green
    GPIOPinWrite(GPIO_PORTF_BASE, GPIO_PIN_1, 0);           // r
    GPIOPinWrite(GPIO_PORTF_BASE, GPIO_PIN_2, 0);           // b
    GPIOPinWrite(GPIO_PORTF_BASE, GPIO_PIN_3, GPIO_PIN_3);  // g
}

/**
 * @brief Function that receives an ack and returns whether ack was
 * success/failure
 *
 * @return uint8_t Ack success/failure
 */
uint8_t receiveAck() {
    MESSAGE_PACKET message;
    uint8_t buffer[1];
    message.buffer = buffer;
    receive_board_message_by_type(&message, ACK_MAGIC, 1);

    return message.buffer[0];
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
