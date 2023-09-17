#include <Arduino.h>
#include <stdlib.h>
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
    return bytes_read;
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

uint8_t fob_to_car_command[34];
uint8_t car_to_fob_nonce[74];
uint8_t fob_to_car_response[500];
int fob_to_length;

void loop() {
  Serial.println("Send Command");
  int result = uart_read(UART1_BASE, fob_to_car_command, 34,10000);
  if (result != 34) {Serial.println("Messed"); return;}
  uart_write(UART1_BASE, car_to_fob_nonce, 74);
  fob_to_length = uart_read(UART1_BASE, fob_to_car_response, 88, 10000);
  Serial.println(fob_to_length);
  for (int i = 0; i < fob_to_length; i++)
  {
    Serial.print(fob_to_car_response[i]);
    Serial.print(" ");
  }
  Serial.println(" ");
  delay(10000);
  // put your main code here, to run repeatedly:
}