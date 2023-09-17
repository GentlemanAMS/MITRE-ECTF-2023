#include <Arduino.h>
#include "driverlib/uart.h"

//Buffer Set
//196 106 249 227 220 247 153 108 37 227 105 27 123 250 181 166

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


void setup() {

  Serial.begin(115200);
  Serial1.begin(115200);
}

int result;


//Car 2
uint8_t fob_to_car_nonce1[18] = {0x56, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
uint8_t car_to_fob_nonce12[34];
uint8_t fob_to_car_nonce2[18] = {0x56, 16, 196, 106, 249, 227, 220, 247, 153, 108, 37, 227, 105, 27, 123, 250, 181, 166};


//Car 3
// uint8_t fob_to_car_nonce1[18] = {86, 16, 220, 149, 58, 11, 245, 255, 197, 60, 197, 48, 91, 2, 22, 108, 214, 234};
// uint8_t car_to_fob_nonce12[34];
// uint8_t fob_to_car_nonce2[18] = {86, 16, 84, 206, 226, 187, 196, 155, 105, 144, 178, 169, 209, 158, 187, 13, 122, 136};



uint8_t car_ack[3];
void loop() {

  uart_write(UART1_BASE, fob_to_car_nonce1, 18);
  result = uart_read(UART1_BASE, car_to_fob_nonce12, 34, 10000);
  if(result!=-1)
  {
    for(int ii=0; ii<34; ii++)
    {
      Serial.print((uint32_t)car_to_fob_nonce12[ii]);
      Serial.print(" ");    
    }
    Serial.println(" ");
    uart_write(UART1_BASE, fob_to_car_nonce2, 18);
    result = uart_read(UART1_BASE, car_ack, 3, 100);
    if (result!=0)
      Serial.println("No Ack");
    else{
      for(int ii=0; ii<3; ii++)
      {
        Serial.print((uint32_t)car_ack[ii]);
        Serial.print(" ");    
      }
    }    
  }
  Serial.println("ABC");
}



//Fob

// uint8_t fob_to_car_nonce1[18];
// uint8_t car_to_fob_nonce12[34] = {86, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255};

// void loop() {

//   result = uart_read(UART1_BASE, fob_to_car_nonce1, 18, 10000);
//   if(result != 0){
//     Serial.println("Skipped");
//     return;
//   } 

//   for (int i = 0; i < 16; i++)
//   {
//     car_to_fob_nonce12[2+i] = fob_to_car_nonce1[2+i];
//   }

//   uart_write(UART1_BASE, car_to_fob_nonce12, 34);
//   result = uart_read(UART1_BASE, fob_to_car_nonce1, 18, 10000);
//   if (result == 0)
//   {
//     for(int ii=0; ii<18; ii++)
//     {
//       Serial.print((uint32_t)fob_to_car_nonce1[ii]);
//       Serial.print(" ");    
//     }
//     Serial.println(" ");    
//   }
//   else{
//     Serial.println("Messed up");
//   }
// }

