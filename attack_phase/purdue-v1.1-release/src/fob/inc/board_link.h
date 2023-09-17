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
#define ACK_SUCCESS 1
#define ACK_FAIL 0

// Headers for Car -> Fob Communication
#define CHALLENGE_HDR (0x43U)         // 67U

// Headers for Fob -> Car Communication
#define UNLOCK_HDR (0x55U)            // 85U
#define UNLOCK_RES_HDR (0x52U)        // 82U
#define START_HDR (0x53U)             // 83U

// Headers for Paired Fob -> Unpaired Fob Communication
#define BOARD_PAIR_HDR (0x60U)        // 96U

// Headers for Fob <-> Host Communication
#define ACK_HDR (0x41U)               // 65U

// Headers for Host -> Fob Communication 
#define HOST_PAIR_HDR (0x50U)         // 80U
#define HOST_FEATURE_HDR (0x46U)      // 70U

// Headers for Fob -> Host Communication
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
  uint8_t header; /**< Header of the message */
  uint8_t message_len; /**< Length of the message */
  uint8_t buffer[MESSAGE_BUFFER_MAX]; /**< Buffer for the message */
} __attribute__((packed)) MESSAGE_PACKET;

/**
 * @brief Set the up comms object
 * 
 */
void setup_comms(void);

/**
 * @brief Delay function
 * 
 * @param ms - number of milliseconds to delay
 */
void delay_ms(uint32_t ms);

/**
 * @brief Receive all messages from the peripheral
 * 
 * @param uart_p - the uart peripheral to use
 */
void recv_all(uint32_t uart_p);

/**
 * @brief Send a message to the board
 * 
 * @param uart_p - the uart peripheral to use
 * @param message - the message to send
 * 
 * @return uint32_t - the length of the message
 */
uint32_t send_message(uint32_t uart_p, MESSAGE_PACKET *message);

/**
 * @brief Send a debug message from the board to the host via UART
 * 
 * @param uart_p - the uart peripheral to use
 * @param message - the message to send to the host
 * @param len - the length of the message
 * 
 * @return uint32_t - the length of the message
*/
uint32_t debug_send_message(uint32_t uart_p, char *message, int len);

/**
 * @brief Send an integer to the host via UART after converting it to a string 
 * 
 * @param uart_p - the uart peripheral to use
 * @param value - the integer to send to the host
 * 
 * @return uint32_t - the length of the message
 */
uint32_t debug_send_int(uint32_t uart_p, uint32_t value);

/**
 * @brief Send an array of bytes to the host via UART
 * 
 * @param uart_p - the uart peripheral to use
 * @param array - the array to send to the host
 * @param len - the length of the array
 * 
 * @return uint32_t - the length of the message
 */
uint32_t debug_send_array(uint32_t uart_p, uint8_t *array, uint32_t len);

/**
 * @brief Receive a message from the board 
 * 
 * @param uart_p - the uart peripheral to use
 * @param message - the message to receive
 * 
 * @return uint8_t - the length of the message
 */
uint8_t receive_message(uint32_t uart_p, MESSAGE_PACKET *message);

/**
 * @brief - Receive a message from the board by type 
 * 
 * @param uart_p - the uart peripheral to use
 * @param message - the message to receive
 * @param type - the type of message to receive
 * 
 * @return uint8_t - the length of the message
 */
uint8_t receive_message_by_type(uint32_t uart_p, MESSAGE_PACKET *message,
                                uint8_t type);

/**
 * @brief - Check if there is a message in the buffer
 * 
 * @param uart_p - the uart peripheral to use 
 * 
 * @return true - if there is a message in the buffer
 * @return false - if there is no message in the buffer
 */
bool has_message(uint32_t uart_p);

#endif
