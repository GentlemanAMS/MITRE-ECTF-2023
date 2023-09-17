#include <Arduino.h>
#include "driverlib/uart.h"

void setup() {
  Serial.begin(115200);
  Serial1.begin(115200); 
  // put your setup code here, to run once:
}


int32_t uart_read(uint32_t uart_port, uint8_t* buffer, uint32_t buffer_length)
{
    uint32_t bytes_read = 0;
    uint32_t start_read_time = millis();

    while(bytes_read < buffer_length){
        if (!UARTCharsAvail(uart_port)) continue;
        buffer[bytes_read] = (uint8_t)UARTCharGet(uart_port);
        bytes_read++;
    }
    return bytes_read;
}

uint8_t buffer[26];

void loop() {

  uart_read(UART1_BASE, buffer, 26);
  for (int ii = 0; ii < 26; ii++)
  {
    Serial.print(buffer[ii]);
    Serial.print(", ");
  }
  // put your main code here, to run repeatedly:
}