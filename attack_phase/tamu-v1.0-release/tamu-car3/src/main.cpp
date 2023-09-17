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
}

uint8_t fob_to_car_unlock_command[2] = {85, 240};
uint8_t car_to_fob_nonce[89];
uint8_t fob_to_car_response[100] = {0, 0, 0, 0, 25, 213, 167, 22, 59, 72, 107, 206, 75, 141, 204, 58, 209, 231, 91, 190, 107, 215, 149, 
                                    219, 162, 231, 68, 76, 201, 55, 218, 2, 239, 4, 5, 161, 184, 132, 225, 252, 49, 47, 236, 38, 128, 70,
                                    59, 248, 245, 191, 17, 117, 85, 215, 88, 136, 48, 178, 40, 223, 247, 173, 55, 72, 193, 103, 147, 134, 
                                    189, 70, 169, 233, 240, 61, 41, 136, 152, 134, 43, 144, 142, 18, 247, 206, 221, 103, 35, 21, 73, 105,
                                    17, 24, 60, 3, 32, 226, 143, 200, 26, 7};


int result;
int length_of_array;
void loop() {
  int i = 0;
  uart_write(UART1_BASE, fob_to_car_unlock_command, 2);
  result = uart_read(UART1_BASE, car_to_fob_nonce, 89, 1000);
  uart_write(UART1_BASE, fob_to_car_response, 100);
  Serial.println("End of Loop");
  delay(10000);
}