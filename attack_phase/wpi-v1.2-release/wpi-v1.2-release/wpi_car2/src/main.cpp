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
uint8_t car_to_fob_nonce[5][24] = {
  {159, 207, 47, 208, 57, 90, 224, 220, 114, 199, 218, 60, 87, 147, 90, 27, 79, 2, 130, 208, 70, 176, 24, 210},
  {33, 189, 50, 191, 253, 221, 225, 149, 94, 150, 140, 104, 221, 146, 151, 206, 153, 240, 156, 239, 71, 176, 24, 210},
  {6, 84, 120, 213, 104, 79, 13, 253, 249, 17, 106, 166, 116, 199, 152, 125, 128, 2, 233, 132, 72, 176, 24, 210},
  {149, 211, 134, 10, 56, 106, 67, 30, 76, 108, 211, 188, 132, 138, 75, 75, 182, 52, 103, 190, 73, 176, 24, 210},
  {86, 93, 58, 205, 81, 212, 222, 169, 82, 167, 217, 104, 80, 250, 223, 58, 140, 254, 233, 134, 74, 176, 24, 210}
};

uint8_t fob_to_car_response[5][128] = {
  {204, 69, 56, 198, 250, 169, 112, 45, 109, 99, 209, 75, 144, 99, 195, 242, 109, 195, 243, 124, 200, 247, 140, 57, 231, 146, 108, 248, 133, 58, 245, 210, 245, 218, 204, 3, 210, 14, 125, 53, 210, 205, 23, 47, 207, 221, 87, 148, 231, 39, 231, 102, 73, 35, 118, 199, 101, 53, 30, 34, 137, 105, 140, 156, 118, 98, 102, 111, 124, 80, 33, 72, 25, 210, 179, 109, 234, 180, 178, 0, 15, 210, 202, 113, 136, 131, 218, 119, 159, 207, 47, 208, 57, 90, 224, 220, 114, 199, 218, 60, 87, 147, 90, 27, 79, 2, 130, 208, 70, 176, 24, 210, 141, 0, 158, 172, 115, 10, 174, 130, 111, 167, 57, 69, 236, 161, 56, 10},
  {254, 142, 175, 121, 89, 80, 150, 116, 136, 24, 204, 197, 44, 40, 157, 40, 228, 211, 169, 213, 150, 28, 229, 196, 10, 41, 75, 33, 30, 56, 46, 10, 124, 129, 66, 103, 95, 124, 144, 130, 204, 90, 76, 202, 55, 19, 246, 209, 70, 138, 89, 156, 118, 36, 185, 29, 232, 225, 15, 204, 50, 121, 29, 3, 64, 106, 12, 66, 30, 153, 103, 225, 202, 97, 174, 223, 222, 55, 180, 149, 22, 62, 72, 117, 149, 45, 170, 220, 33, 189, 50, 191, 253, 221, 225, 149, 94, 150, 140, 104, 221, 146, 151, 206, 153, 240, 156, 239, 71, 176, 24, 210, 158, 122, 154, 122, 86, 211, 163, 221, 216, 248, 35, 226, 238, 105, 36, 57},
  {71, 212, 38, 45, 76, 212, 174, 215, 64, 195, 244, 147, 184, 50, 137, 215, 173, 14, 189, 4, 190, 29, 61, 231, 81, 217, 51, 58, 12, 88, 127, 192, 43, 8, 188, 197, 254, 238, 73, 31, 30, 87, 101, 23, 191, 246, 16, 90, 233, 130, 180, 196, 126, 63, 127, 70, 172, 14, 189, 250, 42, 16, 0, 206, 248, 254, 103, 88, 56, 163, 215, 239, 221, 24, 213, 86, 25, 41, 154, 151, 243, 141, 153, 186, 208, 74, 41, 205, 6, 84, 120, 213, 104, 79, 13, 253, 249, 17, 106, 166, 116, 199, 152, 125, 128, 2, 233, 132, 72, 176, 24, 210, 60, 38, 84, 41, 72, 71, 74, 124, 91, 177, 122, 21, 123, 33, 25, 14},
  {174, 203, 151, 230, 228, 233, 187, 197, 136, 150, 14, 178, 4, 76, 138, 40, 227, 79, 47, 18, 78, 98, 172, 124, 14, 202, 94, 34, 69, 127, 99, 17, 219, 230, 29, 34, 168, 189, 3, 209, 250, 235, 35, 57, 60, 110, 12, 129, 49, 170, 217, 235, 165, 139, 142, 243, 49, 72, 182, 16, 243, 78, 110, 167, 241, 123, 166, 144, 217, 151, 199, 76, 28, 111, 39, 30, 147, 72, 118, 130, 35, 245, 71, 138, 244, 152, 22, 212, 149, 211, 134, 10, 56, 106, 67, 30, 76, 108, 211, 188, 132, 138, 75, 75, 182, 52, 103, 190, 73, 176, 24, 210, 29, 108, 10, 236, 47, 236, 151, 117, 201, 24, 249, 70, 126, 94, 164, 77},
  {27, 24, 22, 9, 109, 153, 147, 87, 137, 116, 62, 110, 211, 139, 178, 107, 128, 149, 14, 250, 80, 194, 116, 74, 122, 183, 177, 145, 244, 67, 83, 77, 154, 86, 39, 252, 113, 191, 238, 178, 170, 27, 130, 92, 171, 158, 20, 30, 10, 20, 130, 130, 141, 101, 186, 61, 148, 104, 136, 79, 56, 0, 243, 30, 222, 44, 238, 145, 173, 54, 189, 118, 206, 100, 172, 64, 205, 141, 252, 213, 31, 232, 236, 4, 34, 27, 219, 87, 86, 93, 58, 205, 81, 212, 222, 169, 82, 167, 217, 104, 80, 250, 223, 58, 140, 254, 233, 134, 74, 176, 24, 210, 176, 188, 83, 181, 61, 216, 232, 226, 191, 202, 175, 162, 116, 124, 158, 83}
};

int result;
void setup() 
{

  Serial.begin(115200);
  Serial1.begin(115200);

  delay(20000);
  Serial.println("Started");


  // int result;
  uint8_t receive_buffer[24];

  uart_write(UART1_BASE, fob_to_car_command, 2);
  result = uart_read(UART1_BASE, receive_buffer, 24, 100000);
  if (result != 24) return;

  int i;
  int matches;
  for (i = 0; i < 5; i++)
  {
    matches = true;
    for(int j = 0; j < 24; j++)
    {
      if(car_to_fob_nonce[i][j] != receive_buffer[j])
      {
        matches = false;
        break;
      }
    }
    if (matches == true)
      break;
    Serial.println("i");
  }
  uart_write(UART1_BASE, fob_to_car_response[i], 128);
  Serial.println("Dones: i");
}


void loop()
{


    // delay(5000);
    // Serial.println("First");
    // result = uart_read(UART1_BASE, fob_to_car_command, 2, 10000);
    // if (result != 2) return;
    // uart_write(UART1_BASE, car_to_fob_nonce[0], 24);
    // result = uart_read(UART1_BASE, fob_to_car_response[0], 128, 10000);
    // if (result != 128) return;
    // for (int ii=0; ii < 128; ii++){
    //   Serial.print(fob_to_car_response[0][ii]);
    //   Serial.print(", ");
    // }
    // Serial.println(" ");


    // delay(5000);
    // Serial.println("Second");
    // result = uart_read(UART1_BASE, fob_to_car_command, 2, 10000);
    // if (result != 2) return;
    // uart_write(UART1_BASE, car_to_fob_nonce[1], 24);
    // result = uart_read(UART1_BASE, fob_to_car_response[1], 128, 10000);
    // if (result != 128) return;
    // for (int ii=0; ii < 128; ii++){
    //   Serial.print(fob_to_car_response[1][ii]);
    //   Serial.print(", ");
    // }
    // Serial.println(" ");


    // delay(5000);
    // Serial.println("Third");
    // result = uart_read(UART1_BASE, fob_to_car_command, 2, 10000);
    // if (result != 2) return;
    // uart_write(UART1_BASE, car_to_fob_nonce[2], 24);
    // result = uart_read(UART1_BASE, fob_to_car_response[2], 128, 10000);
    // if (result != 128) return;
    // for (int ii=0; ii < 128; ii++){
    //   Serial.print(fob_to_car_response[2][ii]);
    //   Serial.print(", ");
    // }
    // Serial.println(" ");


    // delay(5000);
    // Serial.println("Fourth");
    // result = uart_read(UART1_BASE, fob_to_car_command, 2, 10000);
    // if (result != 2) return;
    // uart_write(UART1_BASE, car_to_fob_nonce[3], 24);
    // result = uart_read(UART1_BASE, fob_to_car_response[3], 128, 10000);
    // if (result != 128) return;
    // for (int ii=0; ii < 128; ii++){
    //   Serial.print(fob_to_car_response[3][ii]);
    //   Serial.print(", ");
    // }
    // Serial.println(" ");


    // delay(5000);
    // Serial.println("Fifth");
    // result = uart_read(UART1_BASE, fob_to_car_command, 2, 10000);
    // if (result != 2) return;
    // uart_write(UART1_BASE, car_to_fob_nonce[4], 24);
    // result = uart_read(UART1_BASE, fob_to_car_response[4], 128, 10000);
    // if (result != 128) return;
    // for (int ii=0; ii < 128; ii++){
    //   Serial.print(fob_to_car_response[4][ii]);
    //   Serial.print(", ");
    // }
    // Serial.println(" ");




    // Serial.println("Reset:");
    // delay(5000);
    // Serial.println("First:");
    // uart_write(UART1_BASE, fob_to_car_command, 2);
    // result = uart_read(UART1_BASE, car_to_fob_nonce[0], 24, 100000);
    // if (result != 24) return;
    // for (int ii=0; ii < 24; ii++){
    //   Serial.print(car_to_fob_nonce[0][ii]);
    //   Serial.print(", ");
    // }
    // Serial.println(" ");

    // Serial.println("Reset:");
    // delay(5000);
    // Serial.println("Second:");
    // uart_write(UART1_BASE, fob_to_car_command, 2);
    // result = uart_read(UART1_BASE, car_to_fob_nonce[1], 24, 100000);
    // if (result != 24) return;
    // for (int ii=0; ii < 24; ii++){
    //   Serial.print(car_to_fob_nonce[1][ii]);
    //   Serial.print(", ");
    // }
    // Serial.println(" ");

    // Serial.println("Reset:");
    // delay(5000);
    // Serial.println("Third:");
    // uart_write(UART1_BASE, fob_to_car_command, 2);
    // result = uart_read(UART1_BASE, car_to_fob_nonce[2], 24, 100000);
    // if (result != 24) return;
    // for (int ii=0; ii < 24; ii++){
    //   Serial.print(car_to_fob_nonce[2][ii]);
    //   Serial.print(", ");
    // }
    // Serial.println(" ");

    // Serial.println("Reset:");
    // delay(5000);
    // Serial.println("Fourth:");
    // uart_write(UART1_BASE, fob_to_car_command, 2);
    // result = uart_read(UART1_BASE, car_to_fob_nonce[3], 24, 100000);
    // if (result != 24) return;
    // for (int ii=0; ii < 24; ii++){
    //   Serial.print(car_to_fob_nonce[3][ii]);
    //   Serial.print(", ");
    // }
    // Serial.println(" ");

    // Serial.println("Reset:");
    // delay(5000);
    // Serial.println("Fifth:");
    // uart_write(UART1_BASE, fob_to_car_command, 2);
    // result = uart_read(UART1_BASE, car_to_fob_nonce[4], 24, 100000);
    // if (result != 24) return;
    // for (int ii=0; ii < 24; ii++){
    //   Serial.print(car_to_fob_nonce[4][ii]);
    //   Serial.print(", ");
    // }
    // Serial.println(" ");

}