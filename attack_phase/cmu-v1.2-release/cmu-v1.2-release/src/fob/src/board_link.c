/**
 * @file board_link.h
 * @author Frederich Stine
 * @brief Firmware UART interface implementation.
 * @date 2023
 *
 * This source file is part of an example system for MITRE's 2023 Embedded
 * System CTF (eCTF). This code is being provided only for educational purposes
 * for the 2023 MITRE eCTF competition, and may not meet MITRE standards for
 * quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2023 The MITRE Corporation
 */

#include <stdbool.h>
#include <stdint.h>

#include "tw/hw/hw_memmap.h"
#include "tw/hw/hw_types.h"
#include "tw/hw/hw_uart.h"

#include "tw/gpio.h"
#include "tw/pin_map.h"
#include "tw/sysctl.h"
#include "tw/uart.h"
#include "tw/timer.h"

#include "board_link.h"

/**
 * @brief Set the up board link object
 *
 * UART 1 is used to communicate between boards
 */
void setup_board_link(void) {
  SysCtlPeripheralEnable(SYSCTL_PERIPH_UART1);
  SysCtlPeripheralEnable(SYSCTL_PERIPH_GPIOB);

  GPIOPinConfigure(GPIO_PB0_U1RX);
  GPIOPinConfigure(GPIO_PB1_U1TX);

  GPIOPinTypeUART(GPIO_PORTB_BASE, GPIO_PIN_0 | GPIO_PIN_1);

  // Configure the UART for 115,200, 8-N-1 operation.
  UARTConfigSetExpClk(
      BOARD_UART, SysCtlClockGet(), 115200,
      (UART_CONFIG_WLEN_8 | UART_CONFIG_STOP_ONE | UART_CONFIG_PAR_NONE));

  while (UARTCharsAvail(BOARD_UART)) {
    UARTCharGet(BOARD_UART);
  }
}

/**
 * @brief Send a message between boards
 *
 * @param message pointer to message to send
 * @return uint32_t the number of bytes sent
 */
void send_board_message(uint8_t *message, int len) {
  for (int i = 0; i < len; i++) {
    UARTCharPut(BOARD_UART, message[i]);
  }
}

/**
 * @brief Receive a message between boards
 *
 * @param message pointer to message where data will be received
 * @param len length of the message to be received
 */
void receive_board_message(uint8_t *message, int len) {

  for (int i = 0; i < len; i++) {
    message[i] = (uint8_t)UARTCharGet(BOARD_UART);
  }
}

/**
 * @brief Receive a message between boards with a timeout 
 * 
 * @param message pointer to the message where data will be received
 * @param len length of the message to be received
 * @param timeout_ms timeout in milliseconds
 * @return int8_t 0 on success, -1 on timeout
 */
int8_t receive_message_nonblocking(uint8_t *message, uint32_t len, 
                                         uint32_t timeout_ms, uint32_t UART) {
  // Setting the count down timer to the total number of ticks acoording to
  // timeout_ms
  uint32_t ticks_per_ms = (SysCtlClockGet()/1000);
  TimerLoadSet(WTIMER1_BASE, TIMER_A, ticks_per_ms*timeout_ms);
  TimerIntClear(WTIMER1_BASE, TIMER_TIMA_TIMEOUT);
  TimerEnable(WTIMER1_BASE, TIMER_A);

  for (int i = 0; i < len; i++) {
    while(1){
      if(UARTCharsAvail(UART))
      {
        message[i] = (uint8_t)UARTCharGetNonBlocking(UART);
        break;
      }
      if((TimerIntStatus(WTIMER1_BASE, TIMER_TIMA_TIMEOUT) != 0))
      {
        TimerDisable(WTIMER1_BASE, TIMER_A);
        return -1;
      }
    }
  }
  TimerDisable(WTIMER1_BASE, TIMER_A);
  return 0;
}
