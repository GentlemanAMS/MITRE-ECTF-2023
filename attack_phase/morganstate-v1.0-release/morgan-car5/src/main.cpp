// #include <Arduino.h>
// #include "aead.c"
// #include "api.h"


// // 85, 128, 
// // 253, 201, 178, 16, 186, 81, 93, 115, 149, 113, 39, 216, 175, 195, 52, 65, 171, 222, 176, 16, 179, 169, 115, 254, 228, 209, 245, 86, 178, 174, 145, 61, 
// // 189, 167, 222, 127, 217, 58, 45, 31, 180, 81, 190, 9, 207, 187, 165, 158, 91, 52, 152, 55, 165, 116, 221, 104, 192, 143, 198, 63, 222, 197, 50, 185, 
// // 248, 255, 129, 41, 223, 98, 93, 115, 245, 23, 26, 1, 243, 124, 175, 24, 179, 196, 126, 53, 129, 19, 243, 44, 86, 86, 31, 71, 52, 169, 145, 97, 
// // 250, 177, 246, 97, 153, 19, 104, 42, 70, 181, 172, 253, 80, 250, 40, 179, 153, 161, 3, 132, 201, 95, 197, 188, 39, 143, 100, 126, 232, 98, 43, 18, 

// uint8_t crypt_pin[32] = {
// };

// uint8_t pin[16];

// #define PASSWORD "unlockpleasexoxo"
// #define AUTHENTICATON "2xDq#B5Y00000000"
// #define KEY "oGt4vjXYc7&0VcuP"
// #define NONCE "oGt4vjXYc7&0VcuP"


// void setup() {

//   Serial.begin(115200);
//   // for (int ii = 0; ii < 32; ii++)
//   // {
//   //   crypt_pin[ii] = buffer[32+32+ii];
//   // }
//   // put your setup code here, to run once:
//   uint8_t nonce[16];
//   uint8_t key[16];

//   strncpy((char *)key, KEY, 16);
//   strncpy((char *)nonce, NONCE, 16);



// #define MAX_MESSAGE_LENGTH			    16
// #define MAX_ASSOCIATED_DATA_LENGTH	16

//   unsigned long long  clen;
//   unsigned long long  mlen;
//   unsigned long long  adlen;

//   clen = MAX_MESSAGE_LENGTH + MAX_ASSOCIATED_DATA_LENGTH;
//   mlen = MAX_MESSAGE_LENGTH;
//   adlen = MAX_ASSOCIATED_DATA_LENGTH;

//   crypto_aead_decrypt(pin, &mlen, NULL, crypt_pin, 32, NULL, 0, nonce, key);


// }

// void loop() {

//   for (int ii = 0; ii < 16; ii++){
//     Serial.print(pin[ii]);
//     Serial.print(", ");
//   }
//   Serial.println(" ");
//   delay(1000);
//   // put your main code here, to run repeatedly:
// }




#include "Arduino.h"

#include "driverlib/uart.h"


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

#define RESET_PIN 10
#define UPLOAD_PIN 9

void setup() {
  Serial.begin(115200);
  Serial1.begin(115200);

  GPIOPadConfigSet(GPIO_PORTA_BASE, GPIO_PIN_0, GPIO_STRENGTH_2MA, GPIO_PIN_TYPE_STD_WPU); 
  GPIOPadConfigSet(GPIO_PORTA_BASE, GPIO_PIN_1, GPIO_STRENGTH_2MA, GPIO_PIN_TYPE_STD_WPU);


  GPIOPadConfigSet(GPIO_PORTB_BASE, GPIO_PIN_0, GPIO_STRENGTH_2MA, GPIO_PIN_TYPE_STD_WPU); 
  GPIOPadConfigSet(GPIO_PORTB_BASE, GPIO_PIN_1, GPIO_STRENGTH_2MA, GPIO_PIN_TYPE_STD_WPU);
}

// uint8_t send_unlock[] = {88, 16, 50, 120, 68, 113, 35, 66, 53, 89, 48, 48, 48, 48, 48, 48, 48, 48};
// uint8_t buffer[] = {86, 32, 66, 249, 172, 79, 216, 114, 41, 14, 102, 151, 47, 201, 47, 17, 64, 208, 209, 81, 157, 141, 242, 72, 103, 26, 253, 234, 38, 32, 100, 193, 62, 161, 
// };

// uint8_t receive_nonce[18];

// void loop(){
//   uart_write(UART1_BASE, send_unlock, 18);
//   uart_read(UART1_BASE, receive_nonce, 18, 10000);
//   uart_write(UART1_BASE, buffer, 34);
// }

uint8_t buffer[130];

void loop()
{
  uart_read(UART1_BASE, buffer, 130, 10000);
  for (int ii = 0; ii < 130; ii++){
    Serial.print(buffer[ii]);
    Serial.print(", ");
  }
}

