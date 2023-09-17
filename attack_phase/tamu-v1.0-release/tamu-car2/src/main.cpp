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

int result;

uint8_t fob_to_car_unlock_command[2] = {85, 240};
uint8_t car_to_fob_nonce[5][89] = {
  {208, 231, 171, 125, 147, 237, 66, 132, 219, 93, 186, 136, 205, 158, 158, 26, 19, 184, 153, 39, 240, 116, 31, 119, 47, 50, 210, 170, 141, 102, 208, 206, 139, 239, 241, 77, 58, 141, 58, 27, 128, 172, 126, 8, 147, 153, 35, 203, 50, 94, 215, 113, 96, 104, 58, 192, 77, 152, 133, 170, 187, 232, 211, 10, 82, 212, 139, 153, 57, 250, 50, 168, 225, 116, 175, 106, 17, 237, 149, 105, 162, 52, 84, 114, 32, 68, 231, 153, 240},
  {223, 167, 57, 83, 245, 77, 90, 98, 229, 145, 4, 35, 99, 181, 16, 198, 33, 53, 58, 48, 248, 43, 95, 220, 60, 22, 148, 20, 197, 179, 49, 79, 165, 217, 206, 198, 159, 89, 14, 151, 117, 220, 223, 170, 53, 138, 140, 225, 90, 40, 19, 109, 174, 36, 227, 204, 204, 185, 1, 223, 64, 124, 142, 114, 8, 75, 45, 43, 233, 115, 4, 40, 24, 207, 139, 106, 120, 66, 95, 30, 68, 16, 20, 18, 135, 19, 141, 53, 240},  
  {180, 202, 205, 255, 178, 85, 48, 160, 138, 38, 192, 118, 51, 210, 140, 203, 233, 58, 74, 74, 196, 149, 234, 62, 118, 9, 71, 49, 241, 186, 7, 103, 47, 125, 211, 7, 109, 59, 141, 92, 227, 208, 59, 65, 207, 172, 180, 40, 234, 145, 222, 226, 53, 127, 112, 62, 192, 94, 30, 80, 133, 67, 157, 241, 169, 113, 90, 191, 219, 204, 161, 246, 44, 121, 26, 3, 96, 29, 131, 238, 246, 51, 144, 146, 226, 142, 228, 52, 240},  
  {147, 109, 198, 165, 169, 82, 69, 52, 230, 132, 64, 177, 180, 129, 71, 173, 139, 48, 106, 96, 78, 12, 193, 160, 253, 43, 148, 152, 10, 142, 4, 151, 81, 177, 77, 203, 77, 73, 53, 120, 62, 70, 26, 12, 226, 101, 229, 154, 213, 152, 144, 93, 165, 93, 232, 136, 207, 141, 79, 216, 135, 209, 44, 250, 77, 142, 26, 154, 134, 96, 214, 88, 86, 33, 217, 65, 164, 167, 59, 217, 218, 49, 214, 217, 141, 232, 40, 47, 240},  
  {189, 219, 200, 186, 45, 1, 232, 58, 53, 216, 93, 253, 164, 159, 222, 223, 159, 237, 209, 118, 210, 203, 38, 128, 64, 224, 54, 77, 1, 60, 152, 218, 66, 75, 131, 44, 229, 104, 211, 58, 45, 62, 102, 8, 113, 20, 225, 145, 147, 217, 102, 82, 98, 43, 113, 17, 64, 231, 94, 129, 86, 134, 68, 168, 113, 240, 52, 178, 111, 89, 175, 251, 123, 121, 20, 246, 224, 223, 99, 199, 224, 228, 186, 42, 32, 105, 127, 103, 240}  
};
uint8_t fob_to_car_response[5][100] = {
  {0, 0, 0, 0, 4, 230, 183, 67, 31, 207, 194, 14, 96, 148, 86, 109, 174, 157, 241, 240, 163, 82, 1, 82, 164, 79, 55, 97, 221, 239, 130, 174, 135, 254, 83, 98, 54, 16, 144, 120, 178, 127, 95, 167, 176, 252, 40, 251, 237, 242, 25, 69, 104, 159, 218, 62, 155, 216, 246, 167, 131, 43, 31, 6, 116, 203, 252, 41, 25, 36, 94, 91, 81, 5, 113, 92, 165, 207, 177, 46, 54, 173, 101, 167, 195, 9, 28, 181, 228, 204, 249, 240, 43, 79, 43, 23, 43, 100, 9, 154},
  {0, 0, 0, 0, 181, 151, 246, 3, 94, 207, 133, 186, 163, 182, 148, 223, 133, 210, 58, 96, 185, 9, 236, 166, 230, 222, 26, 141, 229, 198, 172, 157, 104, 181, 186, 158, 81, 102, 175, 123, 97, 53, 125, 85, 162, 158, 67, 93, 134, 209, 15, 191, 255, 169, 148, 13, 41, 209, 43, 32, 81, 94, 57, 253, 37, 158, 0, 13, 172, 51, 245, 81, 17, 223, 142, 41, 122, 24, 46, 220, 95, 101, 211, 231, 251, 121, 174, 173, 46, 145, 237, 100, 133, 137, 169, 167, 133, 221, 252, 142},
  {0, 0, 0, 0, 244, 0, 209, 242, 118, 175, 154, 180, 236, 98, 213, 178, 124, 163, 208, 242, 57, 255, 171, 243, 161, 24, 187, 35, 247, 136, 205, 224, 71, 177, 81, 185, 16, 234, 51, 135, 179, 46, 40, 74, 26, 35, 35, 100, 105, 128, 28, 24, 234, 210, 125, 165, 189, 171, 4, 122, 41, 13, 16, 249, 134, 156, 242, 252, 107, 28, 55, 133, 123, 183, 196, 99, 243, 168, 50, 25, 136, 193, 103, 37, 212, 43, 218, 74, 89, 149, 26, 127, 214, 57, 20, 116, 102, 152, 223, 7},
  {0, 0, 0, 0, 114, 73, 60, 127, 174, 58, 124, 201, 33, 83, 254, 245, 200, 106, 243, 208, 107, 129, 249, 242, 156, 156, 55, 216, 109, 187, 181, 136, 130, 210, 8, 70, 184, 70, 237, 228, 111, 25, 181, 255, 106, 72, 57, 60, 19, 182, 195, 101, 179, 51, 193, 89, 4, 76, 38, 171, 13, 147, 151, 148, 166, 164, 65, 191, 178, 205, 137, 126, 10, 232, 255, 147, 83, 134, 105, 130, 79, 60, 18, 213, 24, 81, 14, 146, 198, 182, 126, 131, 129, 149, 13, 240, 129, 7, 170, 82},
  {0, 0, 0, 0, 191, 15, 55, 44, 161, 94, 120, 204, 12, 138, 20, 60, 166, 251, 52, 32, 129, 90, 20, 48, 92, 59, 96, 61, 100, 157, 83, 214, 217, 141, 57, 94, 130, 110, 182, 66, 55, 74, 118, 148, 120, 48, 77, 101, 91, 135, 179, 46, 70, 225, 172, 219, 82, 157, 230, 251, 254, 184, 169, 5, 28, 239, 121, 185, 17, 233, 54, 232, 40, 51, 70, 200, 170, 162, 61, 178, 243, 196, 10, 159, 81, 241, 142, 101, 216, 151, 26, 208, 73, 230, 182, 46, 96, 225, 129, 137}
};

uint8_t receive_buffer[89];

void setup() {

  Serial.begin(115200);
  Serial1.begin(115200);

  delay(5000);

  uart_write(UART1_BASE, fob_to_car_unlock_command, 2);
  uart_read(UART1_BASE, receive_buffer, 89, 10000);

  int i;
  int matches;
  for (i = 0; i < 5; i++)
  {
    matches = true;
    for(int j = 0; j < 89; j++)
    {
      if(car_to_fob_nonce[i][j] != receive_buffer[j])
      {
        matches = false;
        break;
      }
    }
    if (matches == true)
      break;
  }
  uart_write(UART1_BASE, fob_to_car_response[i], 100);
}


void loop()
{
  
}






/*
void setup() {
  Serial.begin(115200);
  Serial1.begin(115200);

  delay(5000);
  uart_write(UART1_BASE, fob_to_car_unlock_command, 2);
  uart_read(UART1_BASE, car_to_fob_nonce, 89, 10000);
  uart_write(UART1_BASE, fob_to_car_response, 100);
}
*/

/*
  void setup() {
  Serial.begin(115200);
  Serial1.begin(115200);

  delay(5000);
  uart_write(UART1_BASE, fob_to_car_unlock_command, 2);
  uart_read(UART1_BASE, car_to_fob_nonce, 89, 10000);
}
*/

/*
int length_of_array;
void loop()
{

}
*/
/*
void setup()
{
  Serial.begin(115200);
  Serial1.begin(115200);
}

void loop()
{
  Serial.println("1: ");
  result = uart_read(UART1_BASE, fob_to_car_unlock_command, 2, 10000);
  if (result == 0)
  {
    uart_write(UART1_BASE, car_to_fob_nonce[0], 89);
    result = uart_read(UART1_BASE, fob_to_car_response, 100, 10000);
    if (result == 0)
    {
      for (int ii=0; ii < 100; ii++)
      { Serial.print(fob_to_car_response[ii]);
        Serial.print(", ");
      }
      Serial.println(" ");
    }
    else{
      Serial.println("Fucked");
    }
  }

  Serial.println("2: ");
  result = uart_read(UART1_BASE, fob_to_car_unlock_command, 2, 10000);
  if (result == 0)
  {
    uart_write(UART1_BASE, car_to_fob_nonce[1], 89);
    result = uart_read(UART1_BASE, fob_to_car_response, 100, 10000);
    if (result == 0)
    {
      for (int ii=0; ii < 100; ii++)
      { Serial.print(fob_to_car_response[ii]);
        Serial.print(", ");
      }
      Serial.println(" ");
    }
    else{
      Serial.println("Fucked");
    }
  }

  Serial.println("3: ");
  result = uart_read(UART1_BASE, fob_to_car_unlock_command, 2, 10000);
  if (result == 0)
  {
    uart_write(UART1_BASE, car_to_fob_nonce[2], 89);
    result = uart_read(UART1_BASE, fob_to_car_response, 100, 10000);
    if (result == 0)
    {
      for (int ii=0; ii < 100; ii++)
      { Serial.print(fob_to_car_response[ii]);
        Serial.print(", ");
      }
      Serial.println(" ");
    }
    else{
      Serial.println("Fucked");
    }
  }

  Serial.println("4: ");
  result = uart_read(UART1_BASE, fob_to_car_unlock_command, 2, 10000);
  if (result == 0)
  {
    uart_write(UART1_BASE, car_to_fob_nonce[3], 89);
    result = uart_read(UART1_BASE, fob_to_car_response, 100, 10000);
    if (result == 0)
    {
      for (int ii=0; ii < 100; ii++)
      { Serial.print(fob_to_car_response[ii]);
        Serial.print(", ");
      }
      Serial.println(" ");
    }
    else{
      Serial.println("Fucked");
    }
  }

  Serial.println("5: ");
  result = uart_read(UART1_BASE, fob_to_car_unlock_command, 2, 10000);
  if (result == 0)
  {
    uart_write(UART1_BASE, car_to_fob_nonce[4], 89);
    result = uart_read(UART1_BASE, fob_to_car_response, 100, 10000);
    if (result == 0)
    {
      for (int ii=0; ii < 100; ii++)
      { Serial.print(fob_to_car_response[ii]);
        Serial.print(", ");
      }
      Serial.println(" ");
    }
    else{
      Serial.println("Fucked");
    }
  }

}
*/
/*
void loop()
{
  for (int ii=0; ii < 89; ii++)
  {
    Serial.print(car_to_fob_nonce[ii]);
    Serial.print(", ");
  }
  Serial.println(" ");
  delay(10000);
}
*/

/*void loop() {
  int i = 0;
  result = uart_read(UART1_BASE, fob_to_car_unlock_command, 2, 10000);
  if (result == 0)
  {
    uart_write(UART1_BASE, car_to_fob_nonce, 89);
    result = uart_read(UART1_BASE, fob_to_car_response + i, 1, 10000);
    if (result == 0)
    {
      while(result == 0)
      {
        i++;
        result = uart_read(UART1_BASE, fob_to_car_response + i, 1, 10000);
      }
      Serial.println((i));
      length_of_array = i;
      for (int ii=0; ii < length_of_array; ii++)
      { Serial.print(fob_to_car_response[ii]);
        Serial.print(" ");
      }
      Serial.println(" ");
    }
  }
}*/