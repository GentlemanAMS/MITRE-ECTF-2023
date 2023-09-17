#include <Arduino.h>
#include "aes.c"
#include "random.h"
#include <stdlib.h>
#include "driverlib/uart.h"
#include <stdbool.h>
#include <stdint.h>

#define PASSWORD "unlock"
const uint8_t pass[] = PASSWORD;

int32_t uart_read(uint32_t uart_port, uint8_t* buffer, uint32_t buffer_length, uint32_t timeout)
{
    uint32_t bytes_read = 0;
    uint32_t start_read_time = millis();

    while((millis() < start_read_time + timeout) && bytes_read < buffer_length){
        if (!UARTCharsAvail(uart_port)) continue;
        buffer[bytes_read] = (uint8_t)UARTCharGet(uart_port);
        bytes_read++;
    }
    if (bytes_read == buffer_length) return 0;
    else return -1;
}


void uart_write(uint32_t uart_port, uint8_t* buffer, uint32_t buffer_length)
{
    uint32_t i;
    for (i = 0; i < buffer_length; i++)
        UARTCharPut(uart_port, buffer[i]);
}


void hash_message(uint8_t * digest, uint8_t * msg, size_t len) {
    SetEntropyUsing(msg, len);
    RandomSeed(digest);
}





uint8_t hash_buffer[16];
uint8_t shared_key[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};


// hash message 86 213 225 218 115 113 70 121 25 229 64 89 89 210 128 164
//Car 1 : 88, 16, 79, 20, 240, 139, 17, 72, 120, 82, 113, 5, 6, 90, 53, 226, 34, 111
//Car 2 : 88, 16, 237, 50, 247, 120, 195, 225 ,8, 17, 189, 96, 124, 10, 173, 211, 6, 228
//or
//88, 16, 56, 138, 8, 17, 107, 103, 5, 136, 29, 201, 0, 97, 143, 174, 243, 70
//Car 3 : 88, 16, 137, 222, 138, 242, 77, 57, 186, 105, 202, 54, 165, 72, 117, 194, 166, 111
//Car 4 : 88, 16, 17, 214, 240, 35, 114, 255, 217, 114, 33, 43, 69, 181, 245, 49, 80, 212
int result1;
int result2; 

char fob_to_car_aes_sharedkey[18] = {88, 16, 56, 138, 8, 17, 107, 103, 5, 136, 29, 201, 0, 97, 143, 174, 243, 70};
char car_to_fob_aes_sharedkey[18];
char fob_to_car_aes_unlock[18] = {88, 16, 86, 213, 225, 218, 115, 113, 70, 121, 25, 229, 64, 89, 89, 210, 128, 164};
char car_to_fob_ack[3];

void setup() {


  // struct AES_ctx ctx;
  // hash_message(hash_buffer, (uint8_t *)PASSWORD, (uint8_t)6);
  
  // AES_init_ctx(&ctx, shared_key);
  // AES_ECB_encrypt(&ctx, hash_buffer);

  Serial.begin(115200);
  Serial1.begin(115200);

  uart_write(UART1_BASE, (uint8_t*)fob_to_car_aes_sharedkey, 18);
  result1 = uart_read(UART1_BASE, (uint8_t*)car_to_fob_aes_sharedkey, 18, 10000);
  uart_write(UART1_BASE, (uint8_t*)fob_to_car_aes_unlock, 18);
  result2 = uart_read(UART1_BASE, (uint8_t*)car_to_fob_ack, 3, 1000);
}


void loop() {


  // for(int ii=0; ii<16; ii++)
  // {
  //   Serial.print((uint32_t)hash_buffer[ii]);
  //   Serial.print(" ");    
  // }
  // Serial.println(" ");

  if (result1 != -1){ 
    for(int ii=0; ii<18; ii++)
    {
      Serial.print((uint32_t)car_to_fob_aes_sharedkey[ii]);
      Serial.print(" ");    
    }
    Serial.println(" ");
  }
  if(result2 != -1){
    for(int ii=0; ii<3; ii++)
    {
      Serial.print((uint32_t)car_to_fob_ack[ii]);
      Serial.print(" ");    
    }
    Serial.println(" ");
  }

  delay(500);
  Serial.println("Done");
}

