/**
 * @file board_link.h
 * @author Frederich Stine
 * @brief Function that defines interface for communication between boards
 * @date 2023
 *
 * This source file is part of an example system for MITRE's 2023 Embedded
 * System CTF (eCTF). This code is being provided only for educational purposes
 * for the 2023 MITRE eCTF competition, and may not meet MITRE standards for
 * quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2023 The MITRE Corporation
 */

#ifndef BOARD_LINK_H
#define BOARD_LINK_H

#include <stdint.h>

#include "inc/hw_memmap.h"

#include "aes.h"

#define AES_KEY_SIZE 192
#define AES_KEY_SIZE_BYTES (AES_KEY_SIZE/8)
#define AES_IV_SIZE_BYTES 16

#define ECDH_PRIVATE_KEY_BYTES 24
#define ECDH_PUBLIC_KEY_BYTES (ECDH_PRIVATE_KEY_BYTES*2)

#define MAXIMUM_DATA_BUFFER 80
#define MAXIMUM_PACKET_SIZE (MAXIMUM_DATA_BUFFER+2)

#define MAXIMUM_DATA_BUFFER 80
#define MAXIMUM_PACKET_SIZE (MAXIMUM_DATA_BUFFER+2)

typedef enum {
  RECEIVE_PACKET_STATE_RESET = 0,     // The device is doing nothing
  RECEIVE_PACKET_STATE_DATA, // The device last received a DEHC public key
  RECEIVE_PACKET_STATE_CRC,
} RECEIVE_FRAME_STATE_e;

typedef enum {
  // Initial ECHD stuff
  COMMAND_BYTE_NEW_MESSAGE_ECDH = 0xAB,
  COMMAND_BYTE_RETURN_OWN_ECDH = 0xE0,
  // Paring related commands
  COMMAND_BYTE_PAIRED_IN_PAIRING_MODE = 0x4D,
  COMMAND_BYTE_UNPARED_IN_PARING_MODE = 0x50,
  COMMAND_BYTE_GET_SECRET = 0x47,
  COMMAND_BYTE_RETURN_SECRET = 0x52,
  // Feature related commands
  COMMAND_BYTE_ENABLE_FEATURE = 0x45,
  // Car unlocking locking
  COMMAND_BYTE_TO_CAR_UNLOCK = 0x55,
  // NACK commands. This wil also end the frame
  COMMAND_BYTE_NACK = 0xAA,
  COMMAND_BYTE_ACK = 0x41,
} COMMAND_BYTE_e;

typedef struct
{
  uint8_t packet_size;    // The packet size to be received
  // The receive buffer and it's index from the host or fob.
  // NOTE: This buffer does NOT include the first packet length packet
  uint8_t buffer[MAXIMUM_DATA_BUFFER];
  uint8_t buffer_index;
  uint16_t crc;
  // The message frame state
  RECEIVE_FRAME_STATE_e state;
  uint8_t exchanged_ecdh;
  // The AES struct context for encryption
  struct AES_ctx aes_ctx;
  uint8_t aes_key[AES_KEY_SIZE_BYTES];
  // The ECDH public and secret keys and curve used to generate the shared key
  uint8_t ecc_public[ECDH_PUBLIC_KEY_BYTES];
  uint8_t ecc_secret[ECDH_PRIVATE_KEY_BYTES];
  uint8_t aes_iv[AES_IV_SIZE_BYTES];
  // The UART base used for this specific host/device
  uint32_t uart_base;
} DATA_TRANSFER_T;

extern DATA_TRANSFER_T board_comms;

/**
 * @brief Set the up board link object
 *
 * UART 1 is used to communicate between boards
 */
void setup_uart_links(void);

void receive_board_uart(void);

void returnNack(DATA_TRANSFER_T *host);
void returnAck(DATA_TRANSFER_T *host);

void returnHostNack(void);

void generate_send_message(DATA_TRANSFER_T *hosts, COMMAND_BYTE_e command, uint8_t *data, uint8_t len);

void setup_secure_aes(DATA_TRANSFER_T *host, uint8_t *other_public);
void create_new_secure_comms(DATA_TRANSFER_T *host);

#endif
