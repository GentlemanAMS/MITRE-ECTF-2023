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
  Serial.begin(115200);
  Serial1.begin(115200);

  pinMode(10, OUTPUT);
  pinMode(9, OUTPUT);
}

void loop() {

  //Setting up the prey for upload
  digitalWrite(UPLOAD_PIN, LOW);
  delay(100);
  digitalWrite(RESET_PIN, LOW);
  delay(100);
  digitalWrite(RESET_PIN, HIGH);
  delay(100);
  digitalWrite(UPLOAD_PIN, HIGH);
  delay(100);

  //Send start byte 
  Serial.write(0x53);

  //Wait for upload to be complete
  uint8_t receive_upload_confirmation;
  int result = uart_read(UART0_BASE, &receive_upload_confirmation, 1, 100000);
  
  //If acknoweledge is not received, then send default nonce value
  if (result !=0 || receive_upload_confirmation != 0x41)
  {
    uint8_t temp = 0x01;
    for (int ii = 0; ii < 16; ii++){
      Serial.print(temp);
      Serial.print(", ");
    }
    Serial.println(" ");  
    return;
  }

  uint8_t unlock_request[2] = {0x53, 0x00};
  uint8_t challenge[18];
  
  //Once acknowledge is received, do reset
  digitalWrite(RESET_PIN, LOW);
  delay(10);
  digitalWrite(RESET_PIN, HIGH);
  delayMicroseconds(50000);

  //Send unlock request
  uart_write(UART1_BASE, unlock_request, 2);

  //Receive challenge
  result = uart_read(UART1_BASE, challenge, 18, 1000);
  if (result != 0){
    uint8_t temp = 0x01;
    for (int ii = 0; ii < 16; ii++){
      Serial.print(temp);
      Serial.print(", ");
    }
    Serial.println(" ");  
    return;
  }
  else {
    for (int ii = 0; ii < 16; ii++){
      Serial.print(challenge[ii+2]);
      Serial.print(", ");
    }
    Serial.println(" ");  
  }
}