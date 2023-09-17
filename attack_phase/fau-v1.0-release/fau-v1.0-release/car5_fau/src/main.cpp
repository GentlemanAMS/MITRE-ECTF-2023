#include <Arduino.h>
#include "driverlib/uart.h"
void setup() {
  Serial.begin(115200);
  Serial1.begin(115200);
  Serial2.begin(115200);

  // Serial1.setTimeout(1000);
  // Serial2.setTimeout(1000);
}

char fob_to_car_aes_sharedkey[18];
char car_to_fob_aes_sharedkey[18];
char fob_to_car_aes_unlock[18];
char fob_to_car_start_car[12];
char car_to_fob_ack[3];
char fob_to_car_send_features[12];
char fob_to_car_attack_features[4] = {3,1,2,3};
//Serial 1 : fob 
//Serial 2 : car


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


void loop()
{
  int result;

  result = uart_read(UART1_BASE, (uint8_t*)fob_to_car_aes_sharedkey, 18, 1000);
  if (result != -1){ 
    uart_write(UART0_BASE, (uint8_t*)fob_to_car_aes_sharedkey, 18);
    uart_write(UART2_BASE, (uint8_t*)fob_to_car_aes_sharedkey, 18);
  }
  else {
    Serial.println("Messed up 1");
    return;
  }

  result = uart_read(UART2_BASE, (uint8_t*)car_to_fob_aes_sharedkey, 18, 1000);
  if (result != -1){ 
    uart_write(UART0_BASE, (uint8_t*)car_to_fob_aes_sharedkey, 18);
    uart_write(UART1_BASE, (uint8_t*)car_to_fob_aes_sharedkey, 18);
  }
  else {
    Serial.println("Messed up 2");
    return;
  }

  result = uart_read(UART1_BASE, (uint8_t*)fob_to_car_aes_unlock, 18, 1000);
  if (result != -1){ 
    uart_write(UART0_BASE, (uint8_t*)fob_to_car_aes_unlock, 18);
    uart_write(UART2_BASE, (uint8_t*)fob_to_car_aes_unlock, 18);
  }
  else {
    Serial.println("Messed up 3");
    return;
  }


  result = uart_read(UART2_BASE, (uint8_t*)car_to_fob_ack, 3, 1000);
  if (result != -1){ 
    uart_write(UART0_BASE, (uint8_t*)car_to_fob_ack, 3);
    uart_write(UART1_BASE, (uint8_t*)car_to_fob_ack, 3);
  }
  else {
    Serial.println("Messed up 4");
    return;
  }



//////////////////////
// Start car
////////////////////


  result = uart_read(UART1_BASE, (uint8_t*)fob_to_car_aes_sharedkey, 18, 1000);
  if (result != -1){ 
    uart_write(UART0_BASE, (uint8_t*)fob_to_car_aes_sharedkey, 18);
    uart_write(UART2_BASE, (uint8_t*)fob_to_car_aes_sharedkey, 18);
  }
  else {
    Serial.println("Messed up 5");
    return;
  }

  result = uart_read(UART2_BASE, (uint8_t*)car_to_fob_aes_sharedkey, 18, 1000);
  if (result != -1){ 
    uart_write(UART0_BASE, (uint8_t*)car_to_fob_aes_sharedkey, 18);
    uart_write(UART1_BASE, (uint8_t*)car_to_fob_aes_sharedkey, 18);
  }
  else {
    Serial.println("Messed up 6");
    return;
  }

  result = uart_read(UART1_BASE, (uint8_t*)fob_to_car_aes_unlock, 18, 1000);
  if (result != -1){ 
    uart_write(UART0_BASE, (uint8_t*)fob_to_car_aes_unlock, 18);
    uart_write(UART2_BASE, (uint8_t*)fob_to_car_aes_unlock, 18);
  }
  else {
    Serial.println("Messed up 7");
    return;
  }

  result = uart_read(UART1_BASE, (uint8_t*)fob_to_car_send_features, 14, 1000);
  if (result != -1){ 
    uart_write(UART0_BASE, (uint8_t*)fob_to_car_send_features, 14);
    uart_write(UART2_BASE, (uint8_t*)fob_to_car_send_features, 10);
    uart_write(UART2_BASE, (uint8_t*)fob_to_car_attack_features, 4);
  }
  else {
    Serial.println("Messed up 8");
    return;
  }

  Serial.println("Done");

}
