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
    return bytes_read;
}

void uart_write(uint32_t uart_port, uint8_t* buffer, uint32_t buffer_length)
{
    uint32_t i;
    for (i = 0; i < buffer_length; i++)
        UARTCharPut(uart_port, buffer[i]);
}

typedef struct
{
  uint8_t magic;
  uint8_t message_len;
  uint8_t *buffer;
} MESSAGE_PACKET;

#define ACK_MAGIC 0x54
#define PAIR_MAGIC 0x55
#define PAIR_DATA_MAGIC 0x56
#define UNLOCK_MAGIC 0x56
#define CHALLENGE_MAGIC 0x58
#define ANSWER_MAGIC 0x59
#define START_MAGIC 0x60
#define ENABLE_MAGIC 0x61

uint32_t send_board_message(MESSAGE_PACKET *message) {
  UARTCharPut(UART1_BASE, message->magic);
  UARTCharPut(UART1_BASE, message->message_len);

  for (int i = 0; i < message->message_len; i++) {
    UARTCharPut(UART1_BASE, message->buffer[i]);
  }

  return message->message_len;
}

uint32_t receive_board_message(MESSAGE_PACKET *message)
{
    message->magic = (uint8_t)UARTCharGet(UART1_BASE);

    if (message->magic == 0)
    {
        return 0;
    }

    message->message_len = (uint8_t)UARTCharGet(UART1_BASE);

    for (int i = 0; i < message->message_len; i++)
    {
        message->buffer[i] = (uint8_t)UARTCharGet(UART1_BASE);
    }

    return message->message_len;
}

uint32_t receive_board_message_by_type(MESSAGE_PACKET *message, uint8_t type)
{
    do
    {
        receive_board_message(message);
    } while (message->magic != type);

    return message->message_len;
}


void setup() {
  // put your setup code here, to run once:
  Serial.begin(115200);
  Serial1.begin(115200);

}

uint8_t buffer[30];
int result;
void loop() {
  Serial.println("Start");
  result = uart_read(UART1_BASE, buffer, 26, 10000);
  for (int ii=0; ii < result; ii++)
  {
    Serial.print(buffer[ii]);
    Serial.print(", ");
  }
  Serial.println(" ");
}
