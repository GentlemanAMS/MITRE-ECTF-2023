/**
 * @file board_link.h
 * @author Purdue eCTF Team
 * @brief Header file for board_link.c
 * @date 2023
 * 
 * @copyright Copyright (c) 2023 Purdue eCTF Team
 * 
 */

#ifndef BOARD_LINK_H
#define BOARD_LINK_H

#include <stdint.h>

#include "inc/hw_memmap.h"

/** Macro definitions */

// Host - Board Acknowledgement Codes
#define ACK_SUCCESS 1 /* Ackowledgement for Success */
#define ACK_FAIL 0    /* Acknowledgement for Failure */

// Headers for Car -> Fob Communication
#define CHALLENGE_HDR (0x43U)         // 67U

// Headers for Fob -> Car Communication
#define UNLOCK_HDR (0x55U)            // 85U
#define UNLOCK_RES_HDR (0x52U)        // 82U
#define START_HDR (0x53U)             // 83U

// Headers for Car <-> Host Communication
#define ACK_HDR (0x41U)               // 65U

// Headers for Car -> Host Communication
#define HOST_FEATURE_HDR (0x46U)      // 70U
#define HOST_MESSAGE_HDR (0x4DU)      // 77U

// UART Communication HW Configuration
#define BOARD_UART ((uint32_t)UART1_BASE)
#define HOST_UART ((uint32_t)UART0_BASE)

/**
 * @brief Structure for message between boards
 *
 */
#define MESSAGE_BUFFER_MAX 78
typedef struct {
  uint8_t header; /**< Header of message */
  uint8_t message_len; /**< Length of message */
  uint8_t buffer[MESSAGE_BUFFER_MAX]; /**< Buffer for message */
} __attribute__((packed)) MESSAGE_PACKET;

/**
 * @brief Set the up board link object
 *
 * UART 1 is used to communicate between boards
 */
void setup_comms(void);

void delay_ms(uint32_t ms);

/**
 * @brief Send a message between boards
 *
 * @param message pointer to message to send
 * @return uint32_t the number of bytes sent
 */
uint32_t send_message(uint32_t uart_p, MESSAGE_PACKET *message);

uint32_t debug_send_message(uint32_t uart_p, char *message, int len);
uint32_t debug_send_int(uint32_t uart_p, uint32_t value);
uint32_t debug_send_array(uint32_t uart_p, uint8_t *array, uint32_t len);

/**
 * @brief Receive a message between boards
 *
 * @param message pointer to message where data will be received
 * @return uint32_t the number of bytes received
 */
uint8_t receive_message(uint32_t uart_p, MESSAGE_PACKET *message);

/**
 * @brief Function that retrieves messages until the specified message is found
 *
 * @param message pointer to message where data will be received
 * @param type the type of message to receive
 * @return uint32_t the number of bytes received
 */
uint8_t receive_message_by_type(uint32_t uart_p, MESSAGE_PACKET *message,
                                uint8_t type);

bool has_message(uint32_t uart_p);

#endif
