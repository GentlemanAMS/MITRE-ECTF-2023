#include <Arduino.h>
#include "driverlib/uart.h"

void uart_write(uint32_t uart_port, uint8_t* buffer, uint32_t buffer_length)
{
    uint32_t i;
    for (i = 0; i < buffer_length; i++)
        UARTCharPut(uart_port, buffer[i]);
}
uint8_t buffer[26] = {85, 24, 67, 93, 210, 72, 173, 252, 103, 230, 229, 54, 122, 249, 83, 41, 70, 125, 98, 55, 48, 97, 48, 97, 2, 53};

void setup() {
  Serial1.begin(115200);
  // put your setup code here, to run once:
}

void loop() {
  // put your main code here, to run repeatedly:
    uart_write(UART1_BASE, buffer, 26);
    delay(1000);
}