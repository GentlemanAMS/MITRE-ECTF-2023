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

uint8_t buffer[34] = {86, 32, 130, 27, 251, 146, 228, 34, 8, 14, 108, 126, 186, 131, 246, 124, 145, 23, 244, 119, 245, 237, 91, 51, 140, 225, 18, 117, 104, 239, 134, 213, 98, 243,
};

uint8_t buffer_ack[3];
uint8_t buffer_feature[14] = {87, 12, 53, 0, 0, 0, 0, 0, 3, 1, 2, 3};

void loop() {

  // uart_write(UART1_BASE, buffer, 34);
  // Serial.print("Start");
  // uart_read(UART1_BASE, buffer, 34, 1000);
  // for(int ii = 0; ii < 34; ii++)
  // {
  //   Serial.print(buffer[ii]);
  //   Serial.print(", ");
  // }
  // Serial.println(" ");
  // delay(10000);



  uart_write(UART1_BASE, buffer, 34);
  uart_read(UART1_BASE, buffer_ack, 3, 1000);
  uart_write(UART1_BASE, buffer_feature, 14);




  // MESSAGE_PACKET message;
  // message.message_len = 0;
  // message.magic = UNLOCK_MAGIC;
  // uint8_t buffer[256] = {0};
  // message.buffer = buffer;
  // receive_board_message(&message);
  
  // while(true);
}

// uint8_t buffer[256] = {0};
//   message.buffer = buffer;
//   receive_board_message_by_type(&message, CHALLENGE_MAGIC);

//   for(int i=0; i<184; i++){
//     buffer[i] = 0x0;
//   }
//   buffer[184] = 0x08;
//   buffer[185] = 0;
//   buffer[186] = 0;
//   buffer[187] = 0;

//   buffer[188] = 0;
//   buffer[189] = 0xd0;
//   buffer[190] = 0;
//   buffer[191] = 0x40;

//   buffer[192] = 0xf1;
//   buffer[193] = 0x83;
//   buffer[194] = 0;
//   buffer[195] = 0x03;

//   buffer[196] = 0x08;
//   buffer[197] = 0x57;
//   buffer[198] = 0x00;
//   buffer[199] = 0x20;

//   buffer[200] = 0x60;
//   buffer[201] = 0x00;
//   buffer[202] = 0x00;
//   buffer[203] = 0x00;

//   buffer[204] = 0x00;
//   buffer[205] = 0xC2;
//   buffer[206] = 0x01;
//   buffer[207] = 0x00;

//   buffer[208] = 0x00;
//   buffer[209] = 0x24;
//   buffer[210] = 0xF4;
//   buffer[211] = 0x00;

//   buffer[212] = 0x00;
//   buffer[213] = 0xD0;
//   buffer[214] = 0x00;
//   buffer[215] = 0x40;

//   buffer[216] = 0x00;
//   buffer[217] = 0x24;
//   buffer[218] = 0xF4;
//   buffer[219] = 0x00;

//   buffer[220] = 0x00;
//   buffer[221] = 0xD0;
//   buffer[222] = 0x00;
//   buffer[223] = 0x40;

//   // r4
//   buffer[224] = 0x5A;
//   buffer[225] = 0x5A;
//   buffer[226] = 0x5A;
//   buffer[227] = 0x5A;

//   // r5
//   buffer[228] = 0x40;
//   buffer[229] = 0x56;
//   buffer[230] = 0x00;
//   buffer[231] = 0x20;

//   // r6
//   buffer[232] = 0x00;
//   buffer[233] = 0xC0;
//   buffer[234] = 0x00;
//   buffer[235] = 0x40;
  
//   buffer[236] = 0x57;
//   buffer[237] = 0x83;
//   buffer[238] = 0;
//   buffer[239] = 0;

//   buffer[240] = 0;
//   buffer[241] = 0;
//   buffer[242] = 0;
//   buffer[243] = 0;

//   buffer[244] = 0;
//   buffer[245] = 0;
//   buffer[246] = 0;
//   buffer[247] = 0;

//   buffer[248] = 0;
//   buffer[249] = 0;
//   buffer[250] = 0;
//   buffer[251] = 0;

//   buffer[252] = 0;
//   buffer[253] = 0;
//   buffer[254] = 0;
//   buffer[255] = 0; 