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
#include "uart.h"

#include "hmac.h"

#include "aes.h"
#include "inc/tm4c123gh6pm.h"

/*** Structure definitions ***/
// Structure of start_car packet FEATURE_DATA
typedef struct {
  uint8_t car_id[3];
  uint8_t num_active;
  uint8_t features[NUM_FEATURES];
  uint8_t feature_pad[4];
} FEATURE_DATA;

/*** Macro Definitions ***/
// Definitions for unlock message location in EEPROM
#define UNLOCK_EEPROM_LOC 0x7C0
#define UNLOCK_EEPROM_SIZE 64

#define SHA1_DIGEST_SIZE 20

/*** Function definitions ***/
// Core functions - unlockCar and startCar
void unlockCar(void);
void startCar(void);

// Helper functions - sending ack messages
void sendAckSuccess(void);
void sendAckFailure(void);

// Declare password
/* need protection here*/
const uint8_t pass[] = PASSWORD;

// TODO digest check
// uint8_t check_board_message_digest(MESSAGE_PACKET *message);

/**
 * TODO
 * @brief Check message digest
 *
 * @param message pointer to message where data will be received
 * @return uint8_t 0 on success 1 on failure
 */

// uint8_t check_board_message_digest(MESSAGE_PACKET *message) {
// test hmac TODO
// if(message->digest_len == 0){
// return 1;
//}
// uint8_t key[sizeof(HSIM)/sizeof(HSIM[0])] = HSIM;
// unsigned char result[SHA1_DIGEST_SIZE];
// unsigned int result_len;

// test hmac
// hmac_sha1((unsigned char*)key, strlen(key), (unsigned char*)message,
// sizeof(message), result);

// compare the computed HMAC value with the expected value
// if (memcmp(result, message->digest, SHA1_DIGEST_SIZE) == 0)
//{
// return 0; // authentication success
//}
// else
//{
// return 1; // authentication failure
//}
//}


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

  // For nonce genration
  SysCtlClockSet(SYSCTL_SYSDIV_1 | SYSCTL_USE_OSC | SYSCTL_OSC_MAIN |
                 SYSCTL_XTAL_16MHZ);
  SysTickPeriodSet(SysCtlClockGet());
  SysTickEnable();

  while (true) {

    unlockCar();
  }
}

/**
 * @brief Function that handles unlocking of car
 */
void unlockCar(void) {

  // wait for syn
  MESSAGE_SYN_ACK message_syn;
  receive_board_syn_ack(&message_syn, SYN_MAGIC);

  // send syn_ack message
  send_board_syn_ack(SYN_ACK_MAGIC);
  
  //recieve nonce
  MESSAGE_PACKET message_nonce = {0};
  int ret;

  ret = receive_board_message_by_type(&message_nonce, N1_MAGIC);
  
  // check digest
  if (ret == 0){
    return 0;
  }
  
  // get first nonce
  MESSAGE_PAYLOAD *d; 
  d = (MESSAGE_PAYLOAD *)&message_nonce.payload; // cast to payload struct
  
  // get first nonce
  uint32_t nonce1;
  nonce1 = (d->nonce[3]<<24)|(d->nonce[2]<<16)|(d->nonce[1]<<8)|d->nonce[0];
  
  // send first syn message
  send_board_syn_ack(SYN_MAGIC);
  
  // wait for syn_ack
  MESSAGE_SYN_ACK message_ack;
  receive_board_syn_ack(&message_ack, SYN_ACK_MAGIC);
    
  // send nonce2
  uint8_t* nonce;
  nonce = send_board_message(&N2, 11, N2_MAGIC, 0, 0); 
  
  uint32_t nonce2;
  nonce2 = (nonce[3]<<24)|(nonce[2]<<16)|(nonce[1]<<8)|nonce[0];
  
  //converting to char array
  char a1[sizeof(uint32_t)*8+1];
  utoa(nonce1,a1,10);
  char a2[sizeof(uint32_t)*8+1];
  utoa(nonce2,a2,10);
  //concat
  strcat(a1,a2);
  //uart_write(HOST_UART, a1, 11);
  
  //convert to nonce again
  uint32_t concat_nonce;
  char *str2;
  concat_nonce = strtoul(a1,str2,10);
  
  
  uint8_t concat[4];
  concat[3] = (concat_nonce >> 24) & 0xFF;
  concat[2] = (concat_nonce >> 16) & 0xFF;
  concat[1] = (concat_nonce >> 8) & 0xFF;
  concat[0] = concat_nonce & 0xFF;
  
  
  //uart_write(HOST_UART, concat, 4);
  
  
  // wait for syn
  receive_board_syn_ack(&message_syn, SYN_MAGIC);

  // send syn_ack message
  send_board_syn_ack(SYN_ACK_MAGIC);
  

  // Receive packet with some error and digest checking
  MESSAGE_PACKET message = {0};
  

  ret = receive_board_message_by_type(&message, UNLOCK_MAGIC);
  

  if (ret == 0) {
    sendAckFailure();
    return;
  }
  
  // create payload struct
  MESSAGE_PAYLOAD *d2;
  d2 = (MESSAGE_PAYLOAD *)message.payload;
  
  // get the message by xoring 
  uint8_t s_concat_r2[11];
  for(int i=0;i<11;i++){
    s_concat_r2[i] =  d2->buffer[i] ^ concat[i%4];
  }
  
  //uart_write(HOST_UART, s_concat_r2, 11);


  // If the data transfer is the password, unlock
  if (!strcmp((char *)(s_concat_r2), (char *)pass)) {
    uint8_t eeprom_message[64];
    // Read last 64B of EEPROM
    EEPROMRead((uint32_t *)eeprom_message, UNLOCK_EEPROM_LOC,
               UNLOCK_EEPROM_SIZE);
    uart_write(HOST_UART, eeprom_message, UNLOCK_EEPROM_SIZE);
  
    
    // send syn message
    send_board_syn_ack(SYN_MAGIC);
    // wait for syn_ack
    MESSAGE_SYN_ACK message;
    receive_board_syn_ack(&message, SYN_ACK_MAGIC);
    
    // send success ack
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
  // Create a message struct variable for receiving data
  // TODO
  uint8_t car_id[3];
  strncpy(car_id, CAR_ID, 3); // changed, correct?

  MESSAGE_PACKET message = {0};
  int ret;

  // Receive start message and check digest
  ret = receive_board_message_by_type(&message, START_MAGIC);

  for (volatile int i = 0; i < 100000; i++);
  if (ret == 0) {
    sendAckFailure();
  }

  // create payload struct
  MESSAGE_PAYLOAD *d;
  d = (MESSAGE_PAYLOAD *)message.payload;

  // Casting to feature data struct
  FEATURE_DATA *feature_info = (FEATURE_DATA *)d->buffer;
  
  //uart_write(HOST_UART,(char *)feature_info->car_id,3);

  // Verify correct car id
  if (strncmp((char *)car_id, (char *)feature_info->car_id, sizeof(car_id))) {
    return;
  }
  
  
  
  //uart_write(HOST_UART,"Yahoo",5);
  
  /*
  uint8_t num = feature_info->num_active;
  uint8_t num2[1];
  utoa(num,num2,10);
  
  
  uart_write(HOST_UART,num2,1);
  */
  // TODO do we need this?
  // Print out features for all active features
  
  for (int i = 0; i < feature_info->num_active; i++) {
    uint8_t eeprom_message[64];

    uint32_t offset = feature_info->features[i] * FEATURE_SIZE; //TODO feature_info->features[i]
    
    if (offset > FEATURE_END) {
        offset = FEATURE_END;
    }

    EEPROMRead((uint32_t *)eeprom_message, FEATURE_END - offset, FEATURE_SIZE);

    uart_write(HOST_UART, eeprom_message, FEATURE_SIZE);
  }
  
  
}

/**
 * @brief Function to send successful ACK message
 */
void sendAckSuccess(void) {
  // Create packet for successful ack and send
  uint8_t buffer[11] = {0};
  memcpy(buffer, &ACK_SUCCESS, 11);
  send_board_message(buffer, 11, ACK_MAGIC,0,0);
}

/**
 * @brief Function to send unsuccessful ACK message
 */
void sendAckFailure(void) {

  // Create packet for successful ack and send
  uint8_t buffer[11] = {0};
  memcpy(buffer, &ACK_FAIL, 11);
  send_board_message(buffer, 11, ACK_MAGIC, 0, 0);
}
