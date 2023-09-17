#include <Arduino.h>
#include "driverlib/uart.h"

char unlock_req[2];
char nonce[24];

int32_t uart_read(uint32_t uart_port, uint8_t* buffer, uint32_t buffer_length, uint32_t timeout)
{
    uint32_t bytes_read = 0;
    uint32_t start_read_time = millis();

    uint8_t ack = 90;
    uint8_t count = 0;
    
    while((millis() < start_read_time + timeout) && bytes_read < buffer_length){
        if (!UARTCharsAvail(uart_port)) continue;
        buffer[bytes_read] = (uint8_t)UARTCharGet(uart_port);
        bytes_read++;
        count++;
        if (count >= 15){
          UARTCharPut(uart_port, ack);
          count = 0;
        }
    }

    return bytes_read;
}


void uart_write(uint32_t uart_port, uint8_t* buffer, uint32_t buffer_length)
{
    uint32_t i;
    uint8_t count = 0;
    uint8_t ack;
    for (i = 0; i < buffer_length; i++)
    {
        UARTCharPut(uart_port, buffer[i]);
        count++;
        if (count >= 15){
          ack = UARTCharGet(uart_port);
          count = 0;
        }
    }
}

uint8_t fob_to_car_command[2] = {85, 67};
uint8_t car_to_fob_nonce[24];
uint8_t fob_to_car_response[128] = {245, 210, 157, 107, 229, 3, 188, 228, 203, 34, 197, 146, 27, 82, 198, 73, 251, 49, 190, 161, 238, 7, 121, 183, 171, 215, 88, 41, 149, 96, 3, 168, 175, 249, 107, 67, 108, 108, 250, 18, 36, 196, 79, 90, 54, 65, 20, 146, 32, 173, 75, 48, 49, 13, 101, 36, 122, 36, 110, 17, 253, 135, 51, 5, 166, 66, 173, 205, 69, 66, 231, 127, 220, 37, 176, 140, 214, 201, 13, 26, 1, 154, 127, 201, 69, 83, 53, 90, 194, 28, 55, 45, 155, 102, 150, 180, 70, 174, 218, 184, 154, 74, 26, 248, 160, 0, 112, 20, 51, 167, 249, 152, 228, 227, 18, 234, 69, 127, 131, 233, 29, 209, 112, 160, 186, 33, 96, 149};

void setup() {
  Serial.begin(115200);
  Serial1.begin(115200);

  delay(10000);
  Serial.println("Started");
  uart_write(UART1_BASE, fob_to_car_command, 2);
  uart_read(UART1_BASE, car_to_fob_nonce, 24, 10000);
  uart_write(UART1_BASE, fob_to_car_response, 128);
}


void loop()
{
  // int result;
  // delay(5000);
  // Serial.println("Sending started");
  // result = uart_read(UART1_BASE, fob_to_car_command, 2, 10000);
  // if (result != 2) return;
  // Serial.println("Received");
  // uart_write(UART1_BASE, car_to_fob_nonce, 24);
  // result = uart_read(UART1_BASE, fob_to_car_response, 128, 10000);
  // if (result != 128) return;
  // Serial.println("Received response");
  // for (int ii = 0 ; ii < 128; ii++)
  // {
  //   Serial.print(fob_to_car_response[ii]);
  //   Serial.print(" ");
  // }
  // Serial.println(" ");
}