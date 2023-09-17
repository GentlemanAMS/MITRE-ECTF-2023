#include <Arduino.h>
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


void setup() {
  Serial.begin(115200);
  Serial1.begin(115200);
  Serial2.begin(115200);
}

uint8_t fob_to_car_unlock_message[2];
uint8_t car_to_fob_challenge[34];
uint8_t fob_to_car_signature[64+5+2];

int result;

void loop() {
  // put your main code here, to run repeatedly:

  result = uart_read(UART1_BASE, (uint8_t*)fob_to_car_unlock_message, 2, 1000);
  if(result!=-1)
  {
    uart_write(UART2_BASE, fob_to_car_unlock_message, 2);
    for(int ii=0; ii<2; ii++)
    {
      Serial.print(fob_to_car_unlock_message[ii]);
      Serial.print(" ");
    }
    Serial.println(" ");
  

    result = uart_read(UART2_BASE, (uint8_t*)car_to_fob_challenge, 34, 1000);
    if(result!=-1)
    {
      uart_write(UART1_BASE, car_to_fob_challenge, 34);
      for(int ii=0; ii<34; ii++)
      {
        Serial.print(car_to_fob_challenge[ii]);
        Serial.print(" ");
      }
      Serial.println(" ");
    

      result = uart_read(UART1_BASE, (uint8_t*)fob_to_car_signature, 71, 1000);
      if(result!=-1)
      {
        // fob_to_car_signature[3] = 3;
        uart_write(UART2_BASE, fob_to_car_signature, 71);
        for(int ii=0; ii<71; ii++)
        {
          Serial.print(fob_to_car_signature[ii]);
          Serial.print(" ");
        }
        Serial.println(" ");
      }
    }
  }
}