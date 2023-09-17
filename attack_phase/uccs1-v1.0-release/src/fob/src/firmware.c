/**
 * @file main.c
 * @author Frederich Stine
 * @brief eCTF Fob Example Design Implementation
 * @date 2023
 *
 * This source file is part of an example system for MITRE's 2023 Embedded
 * System CTF (eCTF). This code is being provided only for educational purposes
 * for the 2023 MITRE eCTF competition, and may not meet MITRE standards for
 * quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2023 The MITRE Corporation
 */

#include "inc/hw_ints.h"
#include "inc/hw_memmap.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>


#include "inc/tm4c123gh6pm.h"
#include <stdlib.h>
// #include <time.h>

#include "aes.h"
#include "driverlib/eeprom.h"
#include "driverlib/flash.h"
#include "driverlib/gpio.h"
#include "driverlib/interrupt.h"
#include "driverlib/pin_map.h"
#include "driverlib/sysctl.h"
#include "driverlib/systick.h"
#include "driverlib/timer.h"
#include "hmac.h"

#include "driverlib/systick.h"

#include "secrets.h"

#include "board_link.h"
#include "feature_list.h"
#include "uart.h"


// #include "random.h"

#define FOB_STATE_PTR 0x3FC00
#define FLASH_DATA_SIZE                                                        \
  (sizeof(FLASH_DATA) % 4 == 0)                                                \
      ? sizeof(FLASH_DATA)                                                     \
      : sizeof(FLASH_DATA) + (4 - (sizeof(FLASH_DATA) % 4))
#define FLASH_PAIRED 0x00
#define FLASH_UNPAIRED 0xFF
#define PAD2 "00"
#define PAD4 "0000"
#define ENABLE_BUFF 15
/*** Structure definitions ***/

// Defines a struct for the format of an enable message
/*
typedef struct {
  uint8_t feature[16];
} PACKAGE_PAYLOAD;
*/
typedef struct {
  uint8_t payload[16];
 } ENABLE_PACKET_SEC;

typedef struct { 
  uint8_t car_id[3];
  uint8_t pad[5];
  uint8_t feature;
  uint8_t pad2[7];
 } ENABLE_PACKET;

// Defines a struct for the format of a pairing message
typedef struct {
  uint8_t car_id[3];
  uint8_t pin[6];
  uint8_t pad[2];
} PAIR_PACKET1;

typedef struct {
  uint8_t password[11];
} PAIR_PACKET2;

typedef struct {
  uint8_t password[11];
} PAIR_PACKET3;

typedef struct {
  uint8_t password[11];
} PAIR_PACKET4;

// Defines a struct for the format of start message
typedef struct {
  uint8_t car_id[3];
  uint8_t num_active;
  uint8_t features[NUM_FEATURES];
  uint8_t feature_pad[4];
} FEATURE_DATA;

// Defines a struct for storing the state in flash
typedef struct {
  uint8_t paired;
  PAIR_PACKET1 pair_info;
  PAIR_PACKET2 pair_password;
  FEATURE_DATA feature_info;
} FLASH_DATA;

/*** Function definitions ***/
// Core functions - all functionality supported by fob
void saveFobState(FLASH_DATA *flash_data);
void pairFob(FLASH_DATA *fob_state_ram);
void unlockCar(FLASH_DATA *fob_state_ram);
void enableFeature(FLASH_DATA *fob_state_ram);
void startCar(FLASH_DATA *fob_state_ram);

// Helper functions - receive ack message
uint8_t receiveAck();

/**
 * @brief Main function for the fob example
 *
 * Listens over UART and SW1 for an unlock command. If unlock command presented,
 * attempts to unlock door. Listens over UART for pair command. If pair
 * command presented, attempts to either pair a new key, or be paired
 * based on firmware build.
 */
int main(void) {

  // For nonce genration
  SysCtlClockSet(SYSCTL_SYSDIV_1 | SYSCTL_USE_OSC | SYSCTL_OSC_MAIN |
                 SYSCTL_XTAL_16MHZ);
  
  //testing
  //SysCtlClockSet(SYSCTL_SYSDIV_2_5 | SYSCTL_USE_PLL | SYSCTL_OSC_INT);
  SysTickPeriodSet(SysCtlClockGet()); 
  SysTickEnable();

  FLASH_DATA fob_state_ram = {0};
  FLASH_DATA *fob_state_flash = (FLASH_DATA *)FOB_STATE_PTR;

// If paired fob, initialize the system information TODO need protection od paired==1
#if PAIRED == 1
  if (fob_state_flash->paired == FLASH_UNPAIRED) {

    /* need protection */

    strncpy(fob_state_ram.pair_password.password, PASSWORD,
           sizeof(fob_state_ram.pair_password.password));
    strncpy(fob_state_ram.pair_info.pin, PAIR_PIN,
           sizeof(fob_state_ram.pair_info.pin));
    strncpy(fob_state_ram.pair_info.car_id, CAR_ID,
           sizeof(fob_state_ram.pair_info.car_id));
    strncpy(fob_state_ram.pair_info.pad, PAD2,
           sizeof(fob_state_ram.pair_info.pad));
    strncpy(fob_state_ram.feature_info.car_id, CAR_ID,
           sizeof(fob_state_ram.feature_info.car_id));

    fob_state_ram.paired = FLASH_PAIRED;

    saveFobState(&fob_state_ram);
  }
#else
  fob_state_ram.paired = FLASH_UNPAIRED;  
#endif

  if (fob_state_flash->paired == FLASH_PAIRED) {
    memcpy(&fob_state_ram, fob_state_flash, FLASH_DATA_SIZE);
  }

  // This will run on first boot to initialize features
  if (fob_state_ram.feature_info.num_active == 0xFF) {
    fob_state_ram.feature_info.num_active = 0;
    saveFobState(&fob_state_ram);
  }

  // Initialize UART
  uart_init();

  // Initialize board link UART
  setup_board_link();

  // Setup SW1
  GPIOPinTypeGPIOInput(GPIO_PORTF_BASE, GPIO_PIN_4);
  GPIOPadConfigSet(GPIO_PORTF_BASE, GPIO_PIN_4, GPIO_STRENGTH_4MA,
                   GPIO_PIN_TYPE_STD_WPU);

  // Declare a buffer for reading and writing to UART
  uint8_t uart_buffer[10];
  uint8_t uart_buffer_index = 0;

  uint8_t previous_sw_state = GPIO_PIN_4;
  uint8_t debounce_sw_state = GPIO_PIN_4;
  uint8_t current_sw_state = GPIO_PIN_4;

  // Infinite loop for polling UART
  while (true) {

    // Non blocking UART polling
    if (uart_avail(HOST_UART)) {

      uart_buffer_index =
          uart_readline(HOST_UART, uart_buffer, sizeof(uart_buffer));
      if (uart_buffer_index == 0){
        continue;
        }

      if (!(strncmp((char *)uart_buffer, "enable", sizeof(uart_buffer))))

      {
        enableFeature(&fob_state_ram);
        main(); // reset board
      } else if (!(strncmp((char *)uart_buffer, "pair", sizeof(uart_buffer)))) { 
        pairFob(&fob_state_ram);
        main(); // reset board
      }
    }

    current_sw_state = GPIOPinRead(GPIO_PORTF_BASE, GPIO_PIN_4);
    if ((current_sw_state != previous_sw_state) && (current_sw_state == 0)) {
      // Debounce switch
      for (int i = 0; i < 10000; i++)
        ;
      debounce_sw_state = GPIOPinRead(GPIO_PORTF_BASE, GPIO_PIN_4);
      if (debounce_sw_state == current_sw_state) {
        
        
        unlockCar(&fob_state_ram); 
        

        if (receiveAck()) {
          //for (volatile int i = 0; i < 100000; i++);
          startCar(&fob_state_ram);
        }
      }
    }
    previous_sw_state = current_sw_state;
  }
}

/**
 * @brief Function that carries out pairing of the fob
 *
 * @param fob_state_ram pointer to the current fob state in ram
 */

void pairFob(FLASH_DATA *fob_state_ram) {
  MESSAGE_PACKET message = {0};

  // Start pairing transaction - fob is already paired
  if (fob_state_ram->paired == FLASH_PAIRED) {
    int16_t bytes_read;
    uint8_t uart_buffer[8];
    uart_write(HOST_UART, (uint8_t *)"P", 1);
    bytes_read = uart_readline(HOST_UART, uart_buffer,8);
    //uart_write(HOST_UART,(char *)uart_buffer,8);
    //uart_write(HOST_UART,(char *)(char *)fob_state_ram->pair_info.pin,8);

    // TODO

    if (bytes_read <= 8) {
      // If the pin is correct
      if (!(strncmp((char *)uart_buffer, (char *)fob_state_ram->pair_info.pin,6))){
                    //TODO sizeof(uart_buffer)))) {
        
        //three way communication
        uart_write(HOST_UART,"Pair",4);
    
        // send first syn message
        send_board_syn_ack(SYN_MAGIC);
    
        // wait for syn_ack
        MESSAGE_SYN_ACK message_ack;
        receive_board_syn_ack(&message_ack, SYN_ACK_MAGIC);
    
        // send nonce1
        uint8_t* nonce1;
        nonce1 = send_board_message(&N1, 11, N1_MAGIC, 10, 0);
    
    
        // wait for syn
        MESSAGE_SYN_ACK message_syn;
        receive_board_syn_ack(&message_syn, SYN_MAGIC);
    
        // send syn_ack message
        send_board_syn_ack(SYN_ACK_MAGIC);
    
        // reciving nonce2 from car
        MESSAGE_PACKET message = {0};
        uint32_t ret;
    
        ret = receive_boardfob_message_by_type(&message, N2_MAGIC);
 
        // check digest
        if (ret == 0){
           return 0;
         }
    
         // concatenate nonces
    
         MESSAGE_PAYLOAD *d; 
         d = (MESSAGE_PAYLOAD *)&message.payload; // cast to payload struct
    
         // get first nonce
         uint32_t nonce;
         nonce = (nonce1[3]<<24)|(nonce1[2]<<16)|(nonce1[1]<<8)|nonce1[0];
     
         // second nonce
         uint32_t nonce2;
         nonce2 = (d->nonce[3]<<24)|(d->nonce[2]<<16)|(d->nonce[1]<<8)|d->nonce[0];
         //converting to char array
         char a1[sizeof(uint32_t)*8+1];
         utoa(nonce,a1,10);
         char a2[sizeof(uint32_t)*8+1];
         utoa(nonce2,a2,10);
         //concat
         strcat(a1,a2);
     
         //convert to nonce again
         uint32_t concat_nonce;
         char *str2;
         concat_nonce = strtoul(a1,str2,10);
         //uart_write(HOST_UART, a1, sizeof(a1));
     
         uint8_t send_nonce[4];
         send_nonce[3] = (concat_nonce >> 24) & 0xFF;
         send_nonce[2] = (concat_nonce >> 16) & 0xFF;
         send_nonce[1] = (concat_nonce >> 8) & 0xFF;
         send_nonce[0] = concat_nonce & 0xFF;
    
         // send first syn message
         send_board_syn_ack(SYN_MAGIC);
    
         // wait for syn_ack
         receive_board_syn_ack(&message_ack, SYN_ACK_MAGIC);
         
         
        // Pair the new key by sending a PAIR_PACKET structure
        // with required information to unlock door
        // first send the password
        uint8_t buffer[11];
        memcpy(buffer, fob_state_ram->pair_password.password, 11);
        send_board_message(buffer, 11, PAIR_MAGIC, 11, send_nonce); 
        
        // TODO add syn
        // send pairpcket1
        
        // wait for syn_ack
        receive_board_syn_ack(&message_ack, SYN_MAGIC);
        uint8_t buffer_p1[11];
        memcpy(buffer_p1, &fob_state_ram->pair_info, 11);
        send_board_message(buffer_p1, 11, PAIR_MAGIC, 11, send_nonce); 
      }
    }
  }

  // Start pairing transaction - fob is not paired
  else {
    //const uint8_t *msg = (const uint8_t *)"Paired";
    // TODO message.buffer = (uint8_t *)&fob_state_ram->pair_info;
    // wait for syn
    //uart_write(HOST_UART,"start",5);
    MESSAGE_SYN_ACK message_syn;
    receive_board_syn_ack(&message_syn, SYN_MAGIC);

    // send syn_ack message
    send_board_syn_ack(SYN_ACK_MAGIC);
  
    //recieve nonce
    MESSAGE_PACKET message_nonce = {0};
    int ret;

    ret = receive_boardfob_message_by_type(&message_nonce, N1_MAGIC);
  
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
    nonce = send_board_message(&N2, 11, N2_MAGIC, 10, 0); 
  
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
  

   ret = receive_boardfob_message_by_type(&message, PAIR_MAGIC);
  

   if (ret == 0) {
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

    
    
    // get password
    strncpy((char *)fob_state_ram->pair_password.password,
            (char *)s_concat_r2,
            11);
            
    // send syn
    // send first syn message
    send_board_syn_ack(SYN_MAGIC);
            
    // get car id and pairing pin
    MESSAGE_PACKET message_p = {0};
    
    ret = receive_boardfob_message_by_type(&message_p, PAIR_MAGIC);
  

   if (ret == 0) {
     return;
   }
  
   // create payload struct
   MESSAGE_PAYLOAD *d3;
   d3 = (MESSAGE_PAYLOAD *)message_p.payload;
  
  
   
   // get the message by xoring 
   uint8_t s_concat_r3[11];
   for(int i=0;i<11;i++){
     s_concat_r3[i] =  d3->buffer[i] ^ concat[i%4];
   }

   // extract id and pin
  
   PAIR_PACKET1 *pair_info_p;
   
   pair_info_p = (PAIR_PACKET1 *)s_concat_r3;

   
   strncpy((char *)fob_state_ram->feature_info.car_id,
            (char *)pair_info_p->car_id,
            sizeof(fob_state_ram->feature_info.car_id));
            
   strncpy((char *)fob_state_ram->pair_info.car_id,
            (char *)pair_info_p->car_id,
            sizeof(fob_state_ram->feature_info.car_id));
    
   strncpy((char *)fob_state_ram->pair_info.pin,
            (char *)pair_info_p->pin,
            sizeof(fob_state_ram->pair_info.pin));
    
    
    uart_write(HOST_UART, (uint8_t *)"Paired", 6);
    //uart_write(HOST_UART,"okay",4);
    
    fob_state_ram->paired = FLASH_PAIRED;

    saveFobState(fob_state_ram);
  }
}

/**
 * @brief Function that handles enabling a new feature on the fob
 *
 * @param fob_state_ram pointer to the current fob state in ram
 */
void enableFeature(FLASH_DATA *fob_state_ram) {
  if (fob_state_ram->paired == FLASH_PAIRED) { // need protection here?
    const uint8_t *msg = (const uint8_t *)"Enabled";
    uint8_t uart_buffer[ENABLE_BUFF+1];
    
    
    uint8_t key[16];
    
    // TODO: need protection
    uart_readline(HOST_UART, uart_buffer, ENABLE_BUFF);
    
  
    memcpy(key, &TSIM, 16);
    
    for(int i=0;i<ENABLE_BUFF;i++){
      uart_buffer[i] = uart_buffer[i] ^ key[i];
    }
    
    
    ENABLE_PACKET *en;
    en = (ENABLE_PACKET *)uart_buffer;
    
    
    
    
    if (strncmp(fob_state_ram->feature_info.car_id, en->car_id,3) == 0) {
        
    // Feature list full
        if (fob_state_ram->feature_info.num_active == NUM_FEATURES) {
          return;
         }
         
             // Search for feature in list
        for (int i = 0; i < fob_state_ram->feature_info.num_active; i++) {
          if (fob_state_ram->feature_info.features[i] == en->feature) {
            return;
            }
          }
          
        fob_state_ram->feature_info.features[fob_state_ram->feature_info.num_active] = en->feature;
        fob_state_ram->feature_info.num_active++;

        saveFobState(fob_state_ram);
        uart_write(HOST_UART, "Enabled", 7);
  }  
}
}
/**
 * @brief Function that handles the fob unlocking a car
 *
 * @param fob_state_ram pointer to the current fob state in ram
 */
void unlockCar(FLASH_DATA *fob_state_ram) {
  if (fob_state_ram->paired == FLASH_PAIRED) {
    //three way communication
    
    // send first syn message
    send_board_syn_ack(SYN_MAGIC);
    
    // wait for syn_ack
    MESSAGE_SYN_ACK message_ack;
    receive_board_syn_ack(&message_ack, SYN_ACK_MAGIC);
    
    // send nonce1
    uint8_t* nonce1;
    nonce1 = send_board_message(&N1, 11, N1_MAGIC, 0, 0);
    
    
    // wait for syn
    MESSAGE_SYN_ACK message_syn;
    receive_board_syn_ack(&message_syn, SYN_MAGIC);
    
    // send syn_ack message
    send_board_syn_ack(SYN_ACK_MAGIC);
    
    // reciving nonce2 from car
    MESSAGE_PACKET message = {0};
    uint32_t ret;
    
    ret = receive_board_message_by_type(&message, N2_MAGIC);
 
    // check digest
    if (ret == 0){
      return 0;
    }
    
    // concatenate nonces
    
    MESSAGE_PAYLOAD *d; 
    d = (MESSAGE_PAYLOAD *)&message.payload; // cast to payload struct
    
     // get first nonce
     uint32_t nonce;
     nonce = (nonce1[3]<<24)|(nonce1[2]<<16)|(nonce1[1]<<8)|nonce1[0];
     
     // second nonce
     uint32_t nonce2;
     nonce2 = (d->nonce[3]<<24)|(d->nonce[2]<<16)|(d->nonce[1]<<8)|d->nonce[0];
     //converting to char array
     char a1[sizeof(uint32_t)*8+1];
     utoa(nonce,a1,10);
     char a2[sizeof(uint32_t)*8+1];
     utoa(nonce2,a2,10);
     //concat
     strcat(a1,a2);
     
     //convert to nonce again
     uint32_t concat_nonce;
     char *str2;
     concat_nonce = strtoul(a1,str2,10);
     //uart_write(HOST_UART, a1, sizeof(a1));
     
     uint8_t send_nonce[4];
     send_nonce[3] = (concat_nonce >> 24) & 0xFF;
     send_nonce[2] = (concat_nonce >> 16) & 0xFF;
     send_nonce[1] = (concat_nonce >> 8) & 0xFF;
     send_nonce[0] = concat_nonce & 0xFF;
    
    // send first syn message
    send_board_syn_ack(SYN_MAGIC);
    
    // wait for syn_ack
    receive_board_syn_ack(&message_ack, SYN_ACK_MAGIC);
    
    
    uint8_t buffer[11] = {0};
    memcpy(buffer, fob_state_ram->pair_password.password,
           sizeof(fob_state_ram->pair_password.password));

    send_board_message(buffer, 11, UNLOCK_MAGIC, 1, send_nonce); // message.nonce is concatenated, mode 1 is xor
  }
}

/**
 * @brief Function that handles the fob starting a car
 *
 * @param fob_state_ram pointer to the current fob state in ram
 */
void startCar(FLASH_DATA *fob_state_ram) {
// TODO three way comm
  if (fob_state_ram->paired == FLASH_PAIRED) {
    uint8_t buffer[11] = {0};
    memcpy(buffer, &fob_state_ram->feature_info,
           sizeof(fob_state_ram->feature_info));
    send_board_message(buffer, 11, START_MAGIC, 0, 0);
  }
}

/**
 * @brief Function that erases and rewrites the non-volatile data to flash
 *
 * @param info Pointer to the flash data ram
 */
void saveFobState(FLASH_DATA *flash_data) {
  FlashErase(FOB_STATE_PTR);
  FlashProgram((uint32_t *)flash_data, FOB_STATE_PTR, FLASH_DATA_SIZE);
}

/**
 * @brief Function that receives an ack and returns whether ack was
 * success/failure
 *
 * @return uint8_t Ack success/failure
 */
uint8_t receiveAck() {
  
  
  MESSAGE_PACKET message = {0};
  uint32_t ret;
  
  // wait for syn_ack
  MESSAGE_SYN_ACK message_syn;
  receive_board_syn_ack(&message_syn, SYN_MAGIC);
  
  // send syn_ack message
  send_board_syn_ack(SYN_ACK_MAGIC);
  
  ret = receive_board_message_by_type(&message, ACK_MAGIC);
 
  
  if (ret == 0){
      return 0;
  } 

  // create payload struct
  MESSAGE_PAYLOAD *d;
  d = (MESSAGE_PAYLOAD *)message.payload;

  // TODO
  return 1; // d->buffer[0]; //TODO TEST
}
