#include <Arduino.h>
#include "driverlib/uart.h"

// 6{86, 16, 86, 191, 216, 51, 71, 64, 116, 134, 11, 230, 127, 241, 79, 47, 73, 206},
// 7{86, 16, 154, 138, 121, 57, 182, 42, 39, 10, 173, 72, 13, 33, 32, 43, 57, 220},
// 8{86, 16, 225, 191, 138, 158, 162, 255, 141, 151, 50, 129, 116, 179, 224, 137, 233, 153},
// 9{86, 14, 137, 192, 140, 51, 218, 231, 87, 46, 172, 53, 168, 81, 138, 97},
// 10{86, 3, 236, 128, 146},
// 11{86, 16, 53, 204, 231, 142, 251, 53, 118, 209, 15, 134, 150, 139, 70, 191, 157, 152}, 
// 12{86, 16, 38, 164, 25, 171, 194, 156, 45, 119, 241, 96, 42, 71, 22, 202, 24, 174},
// 13{86, 16, 238, 202, 51, 14, 28, 75, 36, 12, 218, 25, 57, 254, 8, 85, 193, 169},
// 14{86, 16, 162, 231, 223, 24, 34, 250, 16, 178, 104, 206, 48, 155, 152, 26, 10, 144},
// 15{86, 16, 142, 73, 227, 95, 115, 64, 57, 236, 37, 14, 225, 129, 236, 126, 181, 80},
// 16{86, 16, 40, 221, 169, 250, 164, 26, 91, 236, 73, 209, 178, 55, 214, 221, 188, 87},
// 17{86, 16, 244, 67, 35, 55, 176, 121, 5, 107, 33, 236, 172, 53, 151, 57, 197, 215},
// 18{86, 16, 101, 214, 135, 255, 9, 71, 110, 57, 108, 197, 243, 168, 113, 82, 100, 39},
// 18{86, 16, 147, 10, 63, 79, 233, 222, 128, 21, 110, 215, 254, 40, 89, 76, 59, 1},
// 19{86, 16, 49, 88, 175, 200, 180, 101, 226, 105, 74, 141, 250, 168, 99, 164, 50, 90},
// 20{86, 16, 44, 23, 185, 38, 170, 255, 120, 254, 91, 27, 124, 37, 97, 105, 96, 186},
// 21{86, 16, 154, 45, 146, 243, 86, 227, 79, 196, 116, 233, 96, 108, 79, 91, 201, 6},
// 22{86, 16, 217, 53, 240, 200, 140, 250, 180, 89, 85, 90, 87, 23, 111, 165, 89, 174},
// 23{86, 2, 245, 220},
// 24{86, 16, 65, 89, 212, 170, 31, 220, 227, 201, 38, 218, 217, 125, 238, 130, 194, 198},
// 25{86, 16, 146, 112, 18, 228, 129, 38, 234, 163, 136, 146, 196, 124, 7, 70, 116, 192},
// 26{86, 16, 161, 216, 46, 9, 241, 83, 215, 236, 117, 216, 30, 154, 216, 126, 23, 47},
// 27{86, 16, 54, 149, 217, 136, 166, 168, 116, 183, 37, 234, 97, 158, 107, 171, 192, 96},
// 28{86, 16, 219, 184, 242, 168, 203, 37, 197, 228, 218, 201, 112, 169, 166, 231, 127, 2},
// 29{86, 4, 110, 41, 251, 62},
// 30{86, 16, 196, 224, 7, 73, 196, 6, 173, 38, 108, 47, 149, 172, 222, 157, 231, 22},
// 31{86, 16, 95, 239, 255, 53, 103, 49, 86, 152, 133, 250, 253, 161, 2, 245, 111, 118},
// 32{86, 16, 106, 159, 141, 170, 56, 68, 30, 52, 183, 33, 44, 159, 153, 157, 111, 121},
// 33{86, 16, 162, 149, 115, 68, 19, 4, 40, 46, 203, 91, 217, 188, 133, 218, 216, 134},
// 34{86, 16, 222, 38, 33, 232, 223, 87, 3, 31, 193, 123, 248, 72, 103, 167, 6, 89},
// 35{86, 16, 215, 131, 162, 171, 90, 214, 78, 177, 21, 57, 6, 236, 100, 123, 26, 32},
// 36{86, 16, 28, 14, 20, 68, 162, 155, 122, 165, 229, 209, 42, 203, 119, 209, 186, 138},
// 37{86, 16, 36, 142, 34, 215, 114, 200, 172, 163, 82, 115, 54, 52, 96, 114, 206, 237},
// 38{86, 16, 86, 220, 208, 251, 153, 228, 81, 175, 164, 214, 62, 14, 33, 243, 160, 185},
// 39{86, 16, 92, 99, 118, 212, 161, 218, 28, 3, 204, 203, 2, 233, 201, 215, 51, 57},
// 40{86, 16, 254, 20, 98, 254, 249, 191, 176, 135, 222, 141, 247, 97, 89, 179, 138, 69},
// 41{86, 16, 149, 249, 105, 49, 15, 174, 192, 35, 86, 192, 97, 78, 158, 196, 143, 64},
// 42{86, 16, 136, 161, 254, 49, 211, 152, 245, 57, 158, 206, 146, 213, 104, 7, 122, 55},
// 43{86, 16, 177, 179, 242, 191, 184, 90, 16, 248, 68, 73, 111, 201, 207, 66, 95, 212},
// 44{86, 16, 159, 187, 15, 73, 100, 233, 224, 41, 22, 184, 226, 47, 176, 192, 64, 14},
// 45{86, 16, 33, 32, 100, 240, 185, 110, 80, 116, 99, 128, 128, 76, 236, 52, 5, 63},
// 46{86, 16, 231, 19, 151, 81, 54, 166, 83, 59, 117, 107, 9, 163, 101, 143, 72, 133},
// 47{86, 16, 79, 252, 113, 47, 50, 134, 18, 8, 130, 1, 252, 126, 116, 236, 253, 100},
// 48{86, 11, 252, 208, 38, 127, 235, 185, 58, 252, 55, 47, 179},
// 49{86, 16, 77, 50, 67, 170, 158, 130, 151, 248, 232, 153, 212, 53, 128, 223, 154, 101},
// 50{86, 16, 1, 242, 171, 234, 107, 82, 138, 124, 165, 80, 57, 164, 70, 197, 253, 146},
// 51{86, 16, 126, 245, 67, 240, 174, 152, 207, 123, 76, 244, 98, 187, 225, 107, 212, 91},
// 52{86, 16, 88, 70, 181, 79, 251, 253, 217, 197, 134, 144, 245, 53, 125, 120, 5, 243},
// 53{86, 16, 10, 185, 55, 85, 243, 125, 7, 252, 161, 51, 147, 117, 48, 189, 154, 82},
// 54{86, 16, 136, 72, 1, 252, 2, 128, 157, 95, 92, 84, 48, 196, 216, 212, 28, 188},
// 55{86, 16, 119, 134, 99, 43, 63, 207, 132, 13, 123, 176, 61, 15, 48, 93, 255, 114},
// 56{86, 16, 45, 72, 140, 49, 148, 192, 42, 202, 209, 185, 85, 192, 53, 224, 237, 215},
// 57{86, 16, 171, 31, 103, 143, 115, 170, 111, 109, 197, 229, 220, 227, 89, 170, 35, 162},
// 58{86, 16, 108, 255, 1, 39, 16, 168, 94, 178, 143, 208, 124, 123, 13, 166, 49, 220},
// 59{86, 16, 100, 35, 142, 204, 140, 157, 19, 19, 221, 79, 124, 128, 53, 155, 26, 93},
// 60{86, 16, 240, 76, 39, 229, 100, 210, 110, 8, 75, 194, 2, 224, 129, 173, 216, 178},
// 61{86, 16, 227, 62, 208, 50, 157, 145, 89, 151, 106, 230, 84, 212, 142, 71, 57, 45},
// 62{86, 16, 192, 206, 227, 21, 178, 20, 195, 164, 15, 9, 177, 224, 69, 9, 115, 125},
// 63{86, 16, 192, 138, 23, 58, 192, 54, 140, 23, 241, 212, 5, 179, 35, 4, 128, 154},


uint8_t fob_to_car[][18] = {
{86, 16, 86, 191, 216, 51, 71, 64, 116, 134, 11, 230, 127, 241, 79, 47, 73, 206},
{86, 16, 154, 138, 121, 57, 182, 42, 39, 10, 173, 72, 13, 33, 32, 43, 57, 220},
{86, 16, 225, 191, 138, 158, 162, 255, 141, 151, 50, 129, 116, 179, 224, 137, 233, 153},
{86, 14, 137, 192, 140, 51, 218, 231, 87, 46, 172, 53, 168, 81, 138, 97},
{86, 3, 236, 128, 146, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
{86, 16, 53, 204, 231, 142, 251, 53, 118, 209, 15, 134, 150, 139, 70, 191, 157, 152}, 
{86, 16, 38, 164, 25, 171, 194, 156, 45, 119, 241, 96, 42, 71, 22, 202, 24, 174},
{86, 16, 238, 202, 51, 14, 28, 75, 36, 12, 218, 25, 57, 254, 8, 85, 193, 169},
{86, 16, 162, 231, 223, 24, 34, 250, 16, 178, 104, 206, 48, 155, 152, 26, 10, 144},
{86, 16, 142, 73, 227, 95, 115, 64, 57, 236, 37, 14, 225, 129, 236, 126, 181, 80},
{86, 16, 40, 221, 169, 250, 164, 26, 91, 236, 73, 209, 178, 55, 214, 221, 188, 87},
{86, 16, 244, 67, 35, 55, 176, 121, 5, 107, 33, 236, 172, 53, 151, 57, 197, 215},
{86, 16, 101, 214, 135, 255, 9, 71, 110, 57, 108, 197, 243, 168, 113, 82, 100, 39},
{86, 16, 147, 10, 63, 79, 233, 222, 128, 21, 110, 215, 254, 40, 89, 76, 59, 1},
{86, 16, 49, 88, 175, 200, 180, 101, 226, 105, 74, 141, 250, 168, 99, 164, 50, 90},
{86, 16, 44, 23, 185, 38, 170, 255, 120, 254, 91, 27, 124, 37, 97, 105, 96, 186},
{86, 16, 154, 45, 146, 243, 86, 227, 79, 196, 116, 233, 96, 108, 79, 91, 201, 6},
{86, 16, 217, 53, 240, 200, 140, 250, 180, 89, 85, 90, 87, 23, 111, 165, 89, 174},
{86, 2, 245, 220, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
{86, 16, 65, 89, 212, 170, 31, 220, 227, 201, 38, 218, 217, 125, 238, 130, 194, 198},
{86, 16, 146, 112, 18, 228, 129, 38, 234, 163, 136, 146, 196, 124, 7, 70, 116, 192},
{86, 16, 161, 216, 46, 9, 241, 83, 215, 236, 117, 216, 30, 154, 216, 126, 23, 47},
{86, 16, 54, 149, 217, 136, 166, 168, 116, 183, 37, 234, 97, 158, 107, 171, 192, 96},
{86, 16, 219, 184, 242, 168, 203, 37, 197, 228, 218, 201, 112, 169, 166, 231, 127, 2},
{86, 4, 110, 41, 251, 62, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
{86, 16, 196, 224, 7, 73, 196, 6, 173, 38, 108, 47, 149, 172, 222, 157, 231, 22},
{86, 16, 95, 239, 255, 53, 103, 49, 86, 152, 133, 250, 253, 161, 2, 245, 111, 118},
{86, 16, 106, 159, 141, 170, 56, 68, 30, 52, 183, 33, 44, 159, 153, 157, 111, 121},
{86, 16, 162, 149, 115, 68, 19, 4, 40, 46, 203, 91, 217, 188, 133, 218, 216, 134},
{86, 16, 222, 38, 33, 232, 223, 87, 3, 31, 193, 123, 248, 72, 103, 167, 6, 89},
{86, 16, 215, 131, 162, 171, 90, 214, 78, 177, 21, 57, 6, 236, 100, 123, 26, 32},
{86, 16, 28, 14, 20, 68, 162, 155, 122, 165, 229, 209, 42, 203, 119, 209, 186, 138},
{86, 16, 36, 142, 34, 215, 114, 200, 172, 163, 82, 115, 54, 52, 96, 114, 206, 237},
{86, 16, 86, 220, 208, 251, 153, 228, 81, 175, 164, 214, 62, 14, 33, 243, 160, 185},
{86, 16, 92, 99, 118, 212, 161, 218, 28, 3, 204, 203, 2, 233, 201, 215, 51, 57},
{86, 16, 254, 20, 98, 254, 249, 191, 176, 135, 222, 141, 247, 97, 89, 179, 138, 69},
{86, 16, 149, 249, 105, 49, 15, 174, 192, 35, 86, 192, 97, 78, 158, 196, 143, 64},
{86, 16, 136, 161, 254, 49, 211, 152, 245, 57, 158, 206, 146, 213, 104, 7, 122, 55},
{86, 16, 177, 179, 242, 191, 184, 90, 16, 248, 68, 73, 111, 201, 207, 66, 95, 212},
{86, 16, 159, 187, 15, 73, 100, 233, 224, 41, 22, 184, 226, 47, 176, 192, 64, 14},
{86, 16, 33, 32, 100, 240, 185, 110, 80, 116, 99, 128, 128, 76, 236, 52, 5, 63},
{86, 16, 231, 19, 151, 81, 54, 166, 83, 59, 117, 107, 9, 163, 101, 143, 72, 133},
{86, 16, 79, 252, 113, 47, 50, 134, 18, 8, 130, 1, 252, 126, 116, 236, 253, 100},
{86, 11, 252, 208, 38, 127, 235, 185, 58, 252, 55, 47, 179, 0, 0, 0, 0, 0},
{86, 16, 77, 50, 67, 170, 158, 130, 151, 248, 232, 153, 212, 53, 128, 223, 154, 101},
{86, 16, 1, 242, 171, 234, 107, 82, 138, 124, 165, 80, 57, 164, 70, 197, 253, 146},
{86, 16, 126, 245, 67, 240, 174, 152, 207, 123, 76, 244, 98, 187, 225, 107, 212, 91},
{86, 16, 88, 70, 181, 79, 251, 253, 217, 197, 134, 144, 245, 53, 125, 120, 5, 243},
{86, 16, 10, 185, 55, 85, 243, 125, 7, 252, 161, 51, 147, 117, 48, 189, 154, 82},
{86, 16, 136, 72, 1, 252, 2, 128, 157, 95, 92, 84, 48, 196, 216, 212, 28, 188},
{86, 16, 119, 134, 99, 43, 63, 207, 132, 13, 123, 176, 61, 15, 48, 93, 255, 114},
{86, 16, 45, 72, 140, 49, 148, 192, 42, 202, 209, 185, 85, 192, 53, 224, 237, 215},
{86, 16, 171, 31, 103, 143, 115, 170, 111, 109, 197, 229, 220, 227, 89, 170, 35, 162},
{86, 16, 108, 255, 1, 39, 16, 168, 94, 178, 143, 208, 124, 123, 13, 166, 49, 220},
{86, 16, 100, 35, 142, 204, 140, 157, 19, 19, 221, 79, 124, 128, 53, 155, 26, 93},
{86, 16, 240, 76, 39, 229, 100, 210, 110, 8, 75, 194, 2, 224, 129, 173, 216, 178},
{86, 16, 227, 62, 208, 50, 157, 145, 89, 151, 106, 230, 84, 212, 142, 71, 57, 45},
{86, 16, 192, 206, 227, 21, 178, 20, 195, 164, 15, 9, 177, 224, 69, 9, 115, 125},
{86, 16, 192, 138, 23, 58, 192, 54, 140, 23, 241, 212, 5, 179, 35, 4, 128, 154}};


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
  // put your setup code here, to run once:
  Serial.begin(115200);
  Serial1.begin(115200);
}

uint8_t receive_buffer[3];

void loop() {
  // put your main code here, to run repeatedly:

  int result = uart_read(UART1_BASE, receive_buffer, 3, 10000);
  if (result == 0)
    if(receive_buffer[0] == 87)
    {
      Serial.println("Receive length:");
      Serial.println(receive_buffer[1]);
      uint8_t row_index = receive_buffer[2] - 6;
      Serial.print("row ");
      Serial.println(row_index);
      if(row_index < 58)
      {
        for (int ii = 0; ii < 18; ii++)
        {
          Serial.print(fob_to_car[row_index][ii]);
          Serial.print(" ");
        }
        Serial.println(" ");
        uint8_t bytes_to_send = fob_to_car[row_index][1] + 2;
        uart_write(UART1_BASE, fob_to_car[row_index], bytes_to_send);
      }
      else{
        Serial.println("Values Gone");
      }
    }
    else{
      Serial.println("Mistake");
    }
  else{
    Serial.println("Didn't receive");
  }
}