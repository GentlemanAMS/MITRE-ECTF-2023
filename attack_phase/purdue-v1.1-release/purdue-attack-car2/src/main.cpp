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
#define BLUE_LED 40
#define GREEN_LED 39
#define RED_LED 30

void setup() {

  uint8_t unlock_request[80] = {0x55, 0x00, 
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

  uint8_t challenge[80];
  uint8_t response[80];

  Serial.begin(115200);
  Serial1.begin(115200);

  pinMode(RESET_PIN, OUTPUT);
  pinMode(UPLOAD_PIN, OUTPUT);
  pinMode(RED_LED, OUTPUT);
  pinMode(GREEN_LED, OUTPUT);
  pinMode(BLUE_LED, OUTPUT);


  //Don't start it
  digitalWrite(RESET_PIN, LOW);
  //Ready to start - start python script
  digitalWrite(GREEN_LED, LOW);
  digitalWrite(BLUE_LED, HIGH);
  delay(1000);
  uint8_t mass = UARTCharGet(UART0_BASE);
  while (mass != 0x53)
    mass = UARTCharGet(UART0_BASE);
  
  digitalWrite(BLUE_LED, LOW);
  delay(10000);
  
  //Start now
  digitalWrite(RESET_PIN, HIGH);

  //Constant delays
  delayMicroseconds(50000);

  //Send unlock request
  uart_write(UART1_BASE, unlock_request, 80);

  //Get Challenge from car
  int result = uart_read(UART1_BASE, challenge, 80, 10000);
  if (result != 0)
    return;

  //Send challenge to PC
  uart_write(UART0_BASE, challenge, 80);

  //Receive response from PC
  result = uart_read(UART0_BASE, response, 80, 10000);
  if (response[0] == 82 && result == 0)
    uart_write(UART1_BASE, response, 80);
  else
    digitalWrite(GREEN_LED, HIGH);

}

void loop() {
  // digitalWrite(30, HIGH);
  // put your main code here, to run repeatedly:
}