#include <Arduino.h>
#include "driverlib/uart.h"
#define PAYLOAD_BUF_SIZE 408

typedef struct {
    uint8_t target;
    uint8_t msg_magic;
    uint64_t c_nonce;
    uint64_t s_nonce;
    size_t payload_size;
    uint8_t payload_buf[PAYLOAD_BUF_SIZE];
    uint8_t payload_hash[32];
} Message;


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


int uart_read_message(uint8_t* message)
{
  uint8_t temp_buffer[4];
  int result = uart_read(UART1_BASE, temp_buffer, 4, 10000);
  if (result == -1) return result;
  int i = 0;
  uint8_t ack = 65;
  while(i < sizeof(Message)) {
    int result = uart_read(UART1_BASE, message+i, 1, 1000);
    if (result == -1) return result;    
    if (i % 8 == 0) 
      uart_write(UART1_BASE, &ack, 1);
    i = i+1;
  }
  return 0;
}

uint8_t uart_magic[] = "0ops";
int uart_write_message(uint8_t* message)
{
  uint8_t ack;
  int result;
  uart_write(UART1_BASE, uart_magic, 4);
  for(size_t i = 0; i < sizeof(Message); i++) {
      uart_write(UART1_BASE, message+i, 1);
      if(i % 8 == 0) {
          result = uart_read(UART1_BASE, &ack, 1, 1000);
          if (result == -1) return -1;
      }
  } 
  return 0; 
}


void setup() {
  // put your setup code here, to run once:
  Serial.begin(115200);
  Serial1.begin(115200);
}

int result;

uint8_t fob_to_car_start[472] = {99, 72, 0, 0, 0, 0, 0, 0, 45, 10, 8, 162, 195, 209, 172, 114, 78, 166, 73, 149, 187, 28, 16, 9, 32, 0, 0, 0, 87, 
                                 33, 218, 57, 195, 100, 45, 74, 229, 137, 12, 8, 129, 237, 228, 97, 129, 9, 76, 214, 42, 150, 242, 247, 
                                 109, 66, 251, 129, 105, 56, 61, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
                                 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
                                 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
                                 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
                                 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
                                 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
                                 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
                                 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
                                 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
                                 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
                                 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 17, 241, 6, 111, 
                                 17, 6, 235, 159, 48, 124, 65, 160, 7, 246, 139, 98, 233, 223, 122, 41, 239, 173, 196, 212, 167, 75, 80, 91, 
                                 177, 125, 245, 177, 0, 0, 0, 0};

uint8_t car_to_fob_challenge[472];
uint8_t fob_to_car_response[472] = {99, 83, 0, 0, 0, 0, 0, 0, 45, 10, 8, 162, 195, 209, 172, 114, 105, 155, 177, 102, 128, 84, 157, 207, 
                                    140, 0, 0, 0, 79, 0, 0, 0, 0, 0, 0, 0, 136, 153, 52, 212, 178, 146, 194, 57, 231, 196, 191, 158, 40, 
                                    234, 73, 117, 99, 250, 75, 151, 111, 205, 172, 98, 171, 141, 42, 191, 35, 4, 37, 29, 255, 255,  255,
                                    255,  255,  255,  255,  255,  255,  255,  255,  255,  255,  255,  255,  255,  255,  255,  255,  255,
                                    255,  255,  255,  255,  255,  255,  255,  255,  255,  255,  255,  255,  255,  255,  255,  255,  255,  
                                    255,  255,  255,  255,  255,  255,  255,  255,  255,  255,  255,  255,  255,  255,  255,  255,  255,  
                                    255,  255,  255,  255,  255,  255,  255,  255,  255,  255,  255,  255,  255,  255,  255,  255,  255,  
                                    255,  255,  255,  255,  255,  255,  255,  255,  255,  255,  255,  255,  255,  255,  255,  255,  255,  
                                    255,  255,  255,  255,  255,  255,  255,  255,  255,  255,  255,  255,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
                                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
                                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
                                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
                                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
                                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
                                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
                                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
                                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 251, 209, 116, 75, 118, 198, 166, 10, 137, 
                                    121, 144, 10, 253, 119, 159, 162, 247, 171, 85, 165, 33, 177, 227, 253, 117, 74, 192, 218, 172, 187, 
                                    5, 153, 0, 0, 0, 0};




void loop() {


  int result = uart_write_message(fob_to_car_start);
  if (result != 0)
  {
    Serial.println("Failed start");
    return;
  }

  result = uart_read_message(car_to_fob_challenge);
  if (result != 0)
  {
    Serial.println("Failed Challenge");
    return;
  }

  result = uart_write_message(fob_to_car_response);
  if (result != 0)
  {
    Serial.println("Response");
    return;
  }















  // Serial.print("Size of Message: ");
  // Serial.println(sizeof(Message));
  // delay(1000);

  // fob_to_car_start_len = uart_read(UART1_BASE, fob_to_car_start, 800, 10000);
  // Serial.print("Number of bytes of fob_to_car_start: ");
  // Serial.println(fob_to_car_start_len);
  // for (int ii = 0; ii < fob_to_car_start_len; ii++)
  // {
  //   Serial.print(fob_to_car_start[ii]);
  //   Serial.print(" ");
  // }
  // Serial.println(" ");

  // uart_write(UART1_BASE, fob_to_car_start, fob_to_car_start_len);
  // car_to_fob_challenge_len = uart_read(UART1_BASE, car_to_fob_challenge, 800, 10000);
  // Serial.print("Number of bytes of car_to_fob_challenge: ");
  // Serial.println(car_to_fob_challenge_len);
  // for (int ii = 0; ii < car_to_fob_challenge_len; ii++)
  // {
  //   Serial.print(car_to_fob_challenge[ii]);
  //   Serial.print(" ");
  // }
  // Serial.println(" ");

  // fob_to_car_start_len = uart_read(UART1_BASE, fob_to_car_start, 800, 10000);
  // uart_write(UART1_BASE, car_to_fob_challenge, car_to_fob_challenge_len);
  // fob_to_car_response_len = uart_read(UART1_BASE, fob_to_car_response, 800, 10000);
  // Serial.print("Number of bytes of fob_to_car_response: ");
  // Serial.println(fob_to_car_response_len);

  delay(1000);
}