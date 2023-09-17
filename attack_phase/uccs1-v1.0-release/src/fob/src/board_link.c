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
#include <stdlib.h>

#include "inc/hw_memmap.h"
#include "inc/hw_types.h"
#include "inc/hw_uart.h"

#include "driverlib/gpio.h"
#include "driverlib/pin_map.h"
#include "driverlib/sysctl.h"
#include "driverlib/systick.h"
#include "driverlib/timer.h"
#include "driverlib/uart.h"

#include "board_link.h"

#define MESSAGE_LEN 32 // need protection?

#include <memory.h>
#include <stdio.h>
#include <string.h>

#include "secrets.h"
#include "aes.h"
#include "hmac.h"

/**
 * @brief Set the up board link object
 *
 * UART 1 is used to communicate between boards
 */
void setup_board_link(void) {
  SysCtlPeripheralEnable(SYSCTL_PERIPH_UART1);
  SysCtlPeripheralEnable(SYSCTL_PERIPH_GPIOB);

  GPIOPinConfigure(GPIO_PB0_U1RX);
  GPIOPinConfigure(GPIO_PB1_U1TX);

  GPIOPinTypeUART(GPIO_PORTB_BASE, GPIO_PIN_0 | GPIO_PIN_1);

  // Configure the UART for 115,200, 8-N-1 operation.
  UARTConfigSetExpClk(
      BOARD_UART, SysCtlClockGet(), 115200,
      (UART_CONFIG_WLEN_8 | UART_CONFIG_STOP_ONE | UART_CONFIG_PAR_NONE));

  UARTFIFOEnable(BOARD_UART);

  while (UARTCharsAvail(BOARD_UART)) {
    UARTCharGet(BOARD_UART);
  }
}

/**
 * @brief Send a message between boards
 *
 * @param message pointer to message to send
 * @return uint32_t the number of bytes sent
 */
uint8_t* send_board_message(uint8_t *buf, uint8_t bufsz, uint8_t type, int xor, uint8_t *nonc) {
  uint8_t s[16];
  uint8_t hk[16];
  uint8_t digest[20];
  uint8_t key[16];

  struct AES_ctx ctx;

  MESSAGE_PAYLOAD payload = {0};

  if ((xor==11 || xor==10)){
    memcpy(s, &FSEC, 16);
  }
  
  else{
    memcpy(s, &PSIM, 16);
    memcpy(key, &TSIM, 16);
  }
  memcpy(hk, &HSIM, 16);

  AES_init_ctx(&ctx, s); // configure keys

  memcpy(payload.buffer, buf, bufsz);

  payload.magic[0] = type;

  // nonce
  uint32_t timer_value = SysTickValueGet();
  uint32_t n = timer_value*20; // TODO timer_value*20;
  
  payload.nonce[3] = (n >> 24) & 0xFF;
  payload.nonce[2] = (n >> 16) & 0xFF;
  payload.nonce[1] = (n >> 8) & 0xFF;

  payload.nonce[0] = n & 0xFF;


  
  // xor mode
  if(xor==1 || xor==11){
  /*
    //test
    uint32_t nonce;
    nonce = (nonc[3]<<24)|(nonc[2]<<16)|(nonc[1]<<8)|nonc[0];
    
   char a1[sizeof(uint32_t)*8+1];
   utoa(nonce,a1,10);
   uart_write(HOST_UART, a1, sizeof(a1));
  */
    //need protection
    for(int i=0;i<11;i++){
      
      payload.buffer[i] = payload.buffer[i] ^ nonc[i%4];
    }
    
    /*
    
    uint8_t buff[11];
    for(int i=0;i<11;i++){
      
      buff[i] = payload.buffer[i] ^ nonc[i%4];
    }
    uart_write(HOST_UART, buff, 11);
    */
  }
    

  // digest
  hmac_sha1(hk, 16, (uint8_t*)&payload, 16, digest);

  // encryption
  AES_ECB_encrypt(&ctx, (uint8_t *)&payload);

  for (int i = 0; i < 16; i++) {
    UARTCharPut(BOARD_UART, digest[i]);
  }

  for (int i = 0; i < 16; i++) {
    UARTCharPut(BOARD_UART, ((uint8_t*)&payload)[i]);
  }
  
  return payload.nonce;
}

/**
 * @brief send a syn/syn_ack message between boards
 *
 * @param message pointer to message where data will be received
 * @return uint32_t the number of bytes received - 0 for error
 */
uint32_t send_board_syn_ack(uint8_t type) {

  MESSAGE_SYN_ACK message;
  message.magic[0] = type;
  
  UARTCharPut(BOARD_UART, message.magic[0]);
  return 1;
}

/**
 * TODO
 * @brief Check message digest
 *
 * @param message pointer to message where data will be received
 * @return uint8_t 1 on success 0 on failure
 */

uint8_t check_board_message_digest(MESSAGE_PACKET *message, uint8_t *hk) {

  uint8_t digest1[20];

  hmac_sha1(hk, 16, message->payload, 16, digest1);

  // compare the computed HMAC value with the expected value
  if (memcmp(digest1, message->digest, 16) == 0) {
    return 1; // authentication success
  } else {
    return 0; // authentication failure
  }
}

/**
 * @brief Receive a message between boards
 *
 * @param message pointer to message where data will be received
 * @return uint32_t the number of bytes received - 0 for error
 */
uint32_t receive_board_message(MESSAGE_PACKET *message) {

  for (int i = 0; i < 16; i++) {
    message->digest[i] = (uint8_t)UARTCharGet(BOARD_UART);
  }

  for (int i = 0; i < 16; i++) {
    message->payload[i] = (uint8_t)UARTCharGet(BOARD_UART);
  }

  // if (message->magic == 0) {
  // return 0;
  //}

  /* TODO: Do crypto here */
  // ret = check_board_message_digest(message);
  // if (ret == 1){
  // return 0;
  //}

  return 1;
}

/**
 * @brief Function that retreives messages until the specified message is found
 *
 * @param message pointer to message where data will be received
 * @param type the type of message to receive
 * @return uint32_t the number of bytes received
 */
uint32_t receive_board_message_by_type(MESSAGE_PACKET *message, uint8_t type) {
  MESSAGE_PAYLOAD *d;
  uint8_t s[16];
  uint8_t hk[16];
  // decryption
  memcpy(s, &PSIM, 16);
  struct AES_ctx ctx;
  AES_init_ctx(&ctx, s); // configure keys
  memcpy(hk, &HSIM, 16); // need protection?

  do {
    receive_board_message(message);



    AES_ECB_decrypt(&ctx, message->payload);

    // casting to payload struct
    d = (MESSAGE_PAYLOAD *)message->payload;
    

  } while (d->magic[0] != type);

  if (check_board_message_digest(message, hk)) {
    return 1; // on digest match
  }

  return 0; // on digest mismatch
}

/**
 * @brief Function that retreives fob messages until the specified message is found
 *
 * @param message pointer to message where data will be received
 * @param type the type of message to receive
 * @return uint32_t the number of bytes received
 */
uint32_t receive_boardfob_message_by_type(MESSAGE_PACKET *message, uint8_t type) {
  MESSAGE_PAYLOAD *d;
  uint8_t s[16];
  uint8_t hk[16];
  struct AES_ctx ctx;

  do {
    receive_board_message(message);

    // decryption
    memcpy(s, &FSEC, 16);
    AES_init_ctx(&ctx, s); // configure keys
    memcpy(hk, &HSIM, 16); // need protection?
    AES_ECB_decrypt(&ctx, message->payload);

    // casting to payload struct
    d = (MESSAGE_PAYLOAD *)message->payload;
    

  } while (d->magic[0] != type);

  if (check_board_message_digest(message, hk)) {
    return 1; // on digest match
  }

  return 0; // on digest mismatch
}

/**
 * @brief Receive a syn/syn_ack message between boards
 *
 * @param message pointer to message where data will be received
 * @return uint32_t the number of bytes received - 0 for error
 */
uint32_t receive_board_syn_ack(MESSAGE_SYN_ACK *message, uint8_t type) {

  do {
    message->magic[0] = (uint8_t)UARTCharGet(BOARD_UART);
  } while (message->magic[0] != type);

  return 1;
}
