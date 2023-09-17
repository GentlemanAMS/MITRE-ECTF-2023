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

#include "secrets.h" //need protection?

#include "inc/hw_memmap.h"

#define ACK_SUCCESS "10129109122"
#define ACK_FAIL    "09012992012"
#define N1          "00229102102"
#define N2          "10119182119"

#define ACK_MAGIC 0x54
#define PAIR_MAGIC 0x55
#define UNLOCK_MAGIC 0x56
#define START_MAGIC 0x57
#define SYN_MAGIC 'S'
#define SYN_ACK_MAGIC 'A' 
#define N1_MAGIC    0x58
#define N2_MAGIC    0x59
#define BOARD_UART ((uint32_t)UART1_BASE)

#include "uart.h"

/**
 * @brief Structure for syn/syn_ack message 
 *
 */

typedef struct
{
  uint8_t       magic[1];
}MESSAGE_SYN_ACK;

/**
 * @brief Structure for message payload
 *
 */

typedef struct
{
  uint8_t       magic[1];
  uint8_t       nonce[4];
  uint8_t       buffer[11];
}MESSAGE_PAYLOAD;

/**
 * @brief Structure for message between boards
 *
 */
typedef struct __attribute__((packed))
{
  uint8_t       digest[16];
  uint8_t       payload[16];
}MESSAGE_PACKET;

/**
 * TODO
 * @brief Check message digest
 *
 * @param message pointer to message where data will be received
 * @return uint8_t 0 on success 1 on failure
 */
 
/*
uint8_t check_board_message_digest(MESSAGE_PACKET *message);
*/

/**
 * @brief Set the up board link object
 *
 * UART 1 is used to communicate between boards
 */
void setup_board_link(void);

/**
 * @brief Send a message between boards
 *
 * @param buf message to send
 * @param bufsz number of bytes in buf
 * @param type the type (magic) of message to send
 * @return uint32_t the number of bytes sent
 */
uint8_t* send_board_message(uint8_t *buf, uint8_t bufsz, uint8_t type, int xor, uint8_t *nonc);

/**
 * TODO
 * @brief Check message digest
 *
 * @param message pointer to message where data will be received
 * @return uint8_t 1 on success 0 on failure
 */

uint8_t check_board_message_digest(MESSAGE_PACKET *message, uint8_t* hk);

/**
 * @brief Receive a message between boards
 *
 * @param message pointer to message where data will be received
 * @return uint32_t the number of bytes received
 */
 
uint32_t receive_board_message(MESSAGE_PACKET *message);

/**
 * @brief Function that retreives messages until the specified message is found
 *
 * @param message pointer to message where data will be received
 * @param type the type of message to receive
 * @return uint32_t the number of bytes received
 */
uint32_t receive_board_message_by_type(MESSAGE_PACKET *message, uint8_t type);

/**
 * @brief Receive a syn/syn_ack message between boards
 *
 * @param message pointer to message where data will be received
 * @return uint32_t the number of bytes received - 0 for error
 */
uint32_t receive_board_syn_ack(MESSAGE_SYN_ACK *message, uint8_t type);

#endif
