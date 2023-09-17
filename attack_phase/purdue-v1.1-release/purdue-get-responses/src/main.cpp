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
#define UNLOCK_PIN 9

void setup() {
  Serial.begin(115200);
  Serial1.begin(115200);

  pinMode(10, OUTPUT);
  pinMode(9, OUTPUT);
  pinMode(RED_LED, OUTPUT);
  pinMode(BLUE_LED, OUTPUT);
}

void loop() {

  digitalWrite(RESET_PIN, LOW);
  delay(50);
  digitalWrite(RESET_PIN, HIGH);
  delay(50);

  //Requesting challenge
  uint8_t request_challenge = 0x52;
  uart_write(UART0_BASE, &request_challenge, 1);

  //Receiving challenge
  uint8_t challenge[80];
  int result = uart_read(UART0_BASE, challenge, 80, 100000);
  digitalWrite(RED_LED, HIGH);
  delay(50);
  digitalWrite(RED_LED, LOW);


  //Start unlock process - Press unlock button
  digitalWrite(UNLOCK_PIN, LOW);
  delay(100);
  digitalWrite(UNLOCK_PIN, HIGH);
  
  //Receive unlock request
  uint8_t unlock_request[80];
  result = uart_read(UART1_BASE, unlock_request, 80, 2000);

  digitalWrite(BLUE_LED, HIGH);
  delay(50);
  digitalWrite(BLUE_LED, LOW);

  //Send challenge
  uart_write(UART1_BASE, challenge, 80);

  //Receive response
  uint8_t response[80 + 80];
  result = uart_read(UART1_BASE, response, 80 + 80, 1000);
  for (int ii = 0; ii < 80; ii++){
    Serial.print(response[ii]);
    Serial.print(", ");
  }
  Serial.println(" ");
}