/**
 * @file board_link.h
 * @author Frederich Stine
 * @brief Firmware UART interface implementation.
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
#include <stdlib.h>

#include "inc/hw_memmap.h"
#include "inc/hw_types.h"
#include "inc/hw_uart.h"

#include "driverlib/gpio.h"
#include "driverlib/pin_map.h"
#include "driverlib/sysctl.h"
#include "driverlib/uart.h"
#include "driverlib/systick.h"

#include "comms.h"
#include "uart.h"
#include "aes.h"
#include "uECC.h"
#include "unewhaven_crc.h"
#include "firmware.h"

#include "blake2.h"

// NOTE NOTE: This flag should be REMOVED for submission.
// It's only here for debugging purposes
// #define RUN_UNENCRYPTED

#ifdef RUN_UNENCRYPTED
#warning("Running UART unencrypted!!!")
#endif

DATA_TRANSFER_T board_comms;

// Curve for ECDH
const struct uECC_Curve_t * curve;

void generate_ecdh_local_keys(DATA_TRANSFER_T *hosts);
void process_received_packet(DATA_TRANSFER_T *host);
void receive_anything_uart(uint32_t uart_base, DATA_TRANSFER_T *host);
int get_random_bytes(uint8_t *buff, unsigned int len);

void setup_uart_links(void) {
  uart_init_host();
  uart_init_board();

  curve = uECC_secp192r1();

  uECC_set_rng(get_random_bytes);

  board_comms.uart_base = UART1_BASE;
  // TODO: Have better reset mechanism
  board_comms.exchanged_ecdh = false;
}

/**
 * Function that gets called when a packet is received for the host UART.
 * 
 * NOTE: Eventually switch this to interrupt
 *       ^^ lol not happening. but if this firmware is to be used in a commercial product
 *          then yes this should be, among many other things
 */
void receive_board_uart(void){
  DATA_TRANSFER_T *host = &board_comms;
  uint8_t uart_char = (uint8_t)uart_readb(BOARD_UART);

  switch(host->state){
    case RECEIVE_PACKET_STATE_RESET:
      host->packet_size = uart_char;
      if(host->packet_size < 3 || host->packet_size >= MAXIMUM_PACKET_SIZE){
        return;
      }
      host->crc = 0;
      host->buffer_index = 0;
      host->state = RECEIVE_PACKET_STATE_DATA;
      break;
    case RECEIVE_PACKET_STATE_DATA:
      host->buffer[host->buffer_index] = uart_char;
      // The case below should never occur, but check it anyways
      if(++host->buffer_index >= MAXIMUM_DATA_BUFFER){
        // todo: handle errors gracefully
        host->state = RECEIVE_PACKET_STATE_RESET;
      }
      if(--host->packet_size == 2){ // If we are on our last packet
        host->state = RECEIVE_PACKET_STATE_CRC;
      }
      break;
    case RECEIVE_PACKET_STATE_CRC:
      host->crc <<= 8;
      host->crc |= uart_char;
      if(--host->packet_size == 0){ // If we are on our last packet
        host->state = RECEIVE_PACKET_STATE_RESET;
        process_received_packet(host);
      }
      break;
    default:
      break;
  }
}

/**
 * Function that processes any received packet from the host
*/
void process_received_packet(DATA_TRANSFER_T *host){
  if(host->buffer_index < 3){  // Smallest message must include at least ony byte and CRC
    // TODO: Raise error: too short
    return;
  }
  // Check CRC with the rest of the message
  uint16_t calc_crc = calculate_crc(host->buffer, host->buffer_index);
  if(calc_crc != host->crc){
    // TODO: Raise error
    return;
  }
  
  if(host->exchanged_ecdh == false){
    // TODO: We are a car. We are to receive command
    if(host->buffer[0] == COMMAND_BYTE_NEW_MESSAGE_ECDH){
      if(host->buffer_index == (1+48+AES_IV_SIZE_BYTES)){
        generate_ecdh_local_keys(host);
        memcpy(host->aes_iv, host->buffer+1+48, AES_IV_SIZE_BYTES);
        // NOTE: This can be a vulnerability if buffer size is not right
        setup_secure_aes(host, &host->buffer[1]);
        // TODO: Might have to re-do the aes key structure
        generate_send_message(host, COMMAND_BYTE_RETURN_OWN_ECDH, host->ecc_public, 48);
        host->exchanged_ecdh = true;
      }
      else{
        returnNack(host);
      }
    }
    else{
      returnNack(host);
    }
  }
  else{
#ifndef RUN_UNENCRYPTED
      AES_CBC_decrypt_buffer(&host->aes_ctx, host->buffer, host->buffer_index);
#endif
    process_board_uart();
  }

}

void generate_ecdh_local_keys(DATA_TRANSFER_T *hosts){
  uECC_make_key(hosts->ecc_public, hosts->ecc_secret, curve);
}

/**
 * Function that returns a NACK and also ends any messaging
*/
void returnNack(DATA_TRANSFER_T *host){
  generate_send_message(host, COMMAND_BYTE_NACK, NULL, 0);
  host->exchanged_ecdh = false;
}

void returnAck(DATA_TRANSFER_T *host){
  generate_send_message(host, COMMAND_BYTE_ACK, NULL, 0);
}

void create_new_secure_comms(DATA_TRANSFER_T *host){
  generate_ecdh_local_keys(host);
  generate_send_message(host, COMMAND_BYTE_NEW_MESSAGE_ECDH, host->ecc_public, 48);
}

void setup_secure_aes(DATA_TRANSFER_T *host, uint8_t *other_public){
  uECC_shared_secret(other_public, host->ecc_secret, host->aes_key, curve);
  AES_init_ctx_iv(&host->aes_ctx, host->aes_key, host->aes_iv);
}

void returnHostNack(void){
  static char *host_ack = "Car is not happy :(\n\0";
  uart_write(HOST_UART, (uint8_t *)host_ack, sizeof(host_ack));
}

/**
 * A common message generator to the host and car/fob
 */
void generate_send_message(DATA_TRANSFER_T *host, COMMAND_BYTE_e command, uint8_t *data, uint8_t len){
  static uint8_t to_send_msg[AES_BLOCKLEN*5];
  memset(to_send_msg, 0, AES_BLOCKLEN*5);
  uint8_t msg_len = 1;
  to_send_msg[1] = command;
  if(len != 0){
    memcpy(&to_send_msg[2], data, len);
    msg_len += len;
  }

  #ifndef RUN_UNENCRYPTED
  // Don't encrypt any COMMAND_BYTE_NEW_MESSAGE_ECDH or COMMAND_BYTE_RETURN_OWN_ECDH commands
  if(!(command == COMMAND_BYTE_NEW_MESSAGE_ECDH || command == COMMAND_BYTE_RETURN_OWN_ECDH)){
    if(msg_len % AES_BLOCKLEN != 0){
      msg_len += AES_BLOCKLEN-(msg_len % AES_BLOCKLEN);
    }
    AES_CBC_encrypt_buffer(&host->aes_ctx, to_send_msg+1, msg_len);
  }
  #endif

  // CRC for overall message
  uint16_t crc = calculate_crc(&to_send_msg[1], msg_len);
  to_send_msg[1+msg_len++] = (crc >> 8) & 0xFF;
  to_send_msg[1+msg_len++] = crc & 0xFF;
  // Length of overall message
  to_send_msg[0] = msg_len;
  msg_len += 1;   // This is only for the next function

  uart_write(host->uart_base, to_send_msg, msg_len);
}

int get_random_bytes(uint8_t *buff, unsigned int len){
  uint8_t random_array[256];
  uint32_t temp;

  srand(SysTickValueGet());

  uint32_t current_time;
  uint8_t rand_time = ((uint8_t)rand() % 10) + 1;
  SysCtlDelay(rand_time);
  current_time = SysTickValueGet();
  temp = rand();

  // Hash temp using Blake2
  blake2s_state hash_state;
  blake2s_init(&hash_state, 16);  // 16-byte hash
  blake2s_update(&hash_state, (uint8_t*)&temp, sizeof(temp));
  uint8_t temp_hash[16];
  blake2s_final(&hash_state, temp_hash, sizeof(temp_hash));

  // Hash time using Blake2
  blake2s_init(&hash_state, 16);  // 16-byte hash
  blake2s_update(&hash_state, (uint8_t*)&current_time, sizeof(current_time));
  uint8_t time_hash[16];
  blake2s_final(&hash_state, time_hash, sizeof(time_hash));

  // XOR current time and temperature
  uint8_t time_temp_xor[4];
  for (int j = 0; j < 16; j++) {
      time_temp_xor[j % 4] ^= temp_hash[j] ^ time_hash[j];
  }

  // Generate an array of 256 8-bit numbers using hash as a random seed
  srand(time_temp_xor[0] + (time_temp_xor[1] << 8) + (time_temp_xor[2] << 16) + (time_temp_xor[3] << 24));
  for (int j = 0; j < 256; j++) {
      random_array[j] = (uint8_t)rand();
  }

  // Randomly select 32 characters from the array and add them to the result character array
  for (int j = 0; j < len; j++) {
      uint8_t index = (uint8_t)rand();
      buff[j] = random_array[index];
  }


  return 1;
}