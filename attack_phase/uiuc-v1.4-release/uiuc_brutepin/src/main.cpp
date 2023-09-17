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
  Serial.begin(921600);
  Serial1.begin(115200);
  pinMode(10, OUTPUT);

  uint8_t start = UARTCharGet(UART0_BASE);
  while(start != 0x01)
    start = UARTCharGet(UART0_BASE);
  // put your setup code here, to run once:
}

void loop() {
  uint8_t pair_start = 0x50;
  uint8_t char_start = 0x42;
  uint8_t receive_buffer[4];
  uint8_t receive;
  uint8_t pair_done = 0x44;
  uint8_t pair_not_done = 0x45;


  //Start pairing process - send 'P' to host tools
  uart_write(UART0_BASE, &pair_start, 1);

  //Receive 4 bytes of 'PIN' data from fob
  int result = uart_read(UART1_BASE, receive_buffer, 4, 1000);
  if (result != 0){
    digitalWrite(10, LOW);
    delay(2);
    digitalWrite(10, HIGH);
    return;    
  }

  //Send MAGIC_PAIR_ACK to fob
  uart_write(UART1_BASE, &char_start, 1);

  // //Hopefull receives a reply
  result = uart_read(UART1_BASE, &receive, 1, 840);

  //Reset
  digitalWrite(10, LOW);
  delay(2);
  digitalWrite(10, HIGH);
  
  if (result == 0 && receive == 0x43){
    uart_write(UART0_BASE, &pair_done, 1);
  }
  else {
    // UARTCharGet(UART1_BASE);
    uart_write(UART0_BASE, &pair_not_done, 1);
  }
  delay(40);

}