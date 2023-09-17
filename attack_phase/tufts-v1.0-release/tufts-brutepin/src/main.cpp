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
  // put your setup code here, to run once:
}

uint8_t buffer[34];

void loop() {
  if (UARTCharsAvail(UART1_BASE))
  {
    uart_read(UART1_BASE, buffer, 34, 10000);
    for (int ii = 0; ii < 34; ii++){
      Serial.print(buffer[ii]);
      Serial.print(", ");
    }
  }
  // put your main code here, to run repeatedly:
}