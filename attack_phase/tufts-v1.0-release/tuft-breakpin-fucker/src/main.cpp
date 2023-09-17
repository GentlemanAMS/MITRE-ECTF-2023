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

#define RESET_PIN 10
#define UPLOAD_PIN 9

void setup() {

  uint8_t unlock_request[2] = {0x53, 0x00};
  uint8_t challenge[18];
  uint8_t response[19];


  Serial.begin(115200);
  Serial1.begin(115200);

  pinMode(10, OUTPUT);
  pinMode(9, OUTPUT);
  pinMode(30, OUTPUT);
  pinMode(40, OUTPUT);
  pinMode(39, OUTPUT);

  digitalWrite(RESET_PIN, LOW);
  digitalWrite(40, HIGH);
  delay(1000);
  uint8_t mass = UARTCharGet(UART0_BASE);
  while (mass != 0x53)
    mass = UARTCharGet(UART0_BASE);
  digitalWrite(40, LOW);
  delay(10000);
  digitalWrite(RESET_PIN, HIGH);

  delayMicroseconds(50000);

  //Send unlock request
  uart_write(UART1_BASE, unlock_request, 2);

  //Get Challenge from car
  int result = uart_read(UART1_BASE, challenge, 18, 10000);
  if (result != 0)
    return;

  //Send challenge to PC
  uart_write(UART0_BASE, &challenge[2], 16);

  //Receive response from PC
  result = uart_read(UART0_BASE, response, 19, 10000);
  if (response[0] == 0x59 && result == 0)
    uart_write(UART1_BASE, &response[1], 18);
  else
    digitalWrite(39, HIGH);

}

void loop() {
  // digitalWrite(30, HIGH);
  // put your main code here, to run repeatedly:
}