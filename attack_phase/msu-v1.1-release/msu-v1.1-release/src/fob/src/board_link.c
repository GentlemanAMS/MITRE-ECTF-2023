/**
 * @file board_link.h
 * @author Spartan State Security Team
 * @brief Firmware UART interface implementation.
 * @date 2023
 *
 * This source file is part of our designed system
 * for MITRE's 2023 Embedded System CTF (eCTF).
 */

#include <stdbool.h>
#include <stdint.h>

#include "inc/hw_memmap.h"
#include "inc/hw_types.h"
#include "inc/hw_uart.h"

#include "driverlib/gpio.h"
#include "driverlib/pin_map.h"
#include "driverlib/sysctl.h"
#include "driverlib/uart.h"

#include "sb_all.h"

#include "board_link.h"
#include "uart.h"
#include "firmware.h"

/**
 * @brief Initialize the board link interface.
 *
 * UART 1 is used to communicate between boards,
 * whether pFob or uFob or Car.
 */
void setup_board_link(void) {
  SysCtlPeripheralEnable(SYSCTL_PERIPH_UART1);
  SysCtlPeripheralEnable(SYSCTL_PERIPH_GPIOB);

  GPIOPinConfigure(GPIO_PB0_U1RX);
  GPIOPinConfigure(GPIO_PB1_U1TX);

  GPIOPinTypeUART(GPIO_PORTB_BASE, GPIO_PIN_0 | GPIO_PIN_1);

  // Configure the UART for 115,200, 8-N-1 operation.
  UARTConfigSetExpClk(
      BOARD_UART, SPEED, BAUD,
      (UART_CONFIG_WLEN_8 | UART_CONFIG_STOP_ONE | UART_CONFIG_PAR_NONE));

  while (UARTCharsAvail(BOARD_UART)) {
    UARTCharGet(BOARD_UART);
  }
}

/**
 * @brief Request the car to begin unlock sequence
 */
void request_unlock(void) {
  uart_writeb(CAR_UART, (uint8_t)UNLOCK_REQ);
}

/**
 * @brief Receives the challenge from the car device
 * 
 * @param challenge [out] The challenge being written
 */
void get_challenge(CHALLENGE *challenge) {
  while(uart_readb(CAR_UART) != CHAL_START);
  uart_read(CAR_UART, (uint8_t *)challenge, sizeof(CHALLENGE));
}

/**
 * @brief Finalizes the unlock attempt by sending the
 * generated response to the car device
 * 
 * @param response [in] The response to send
 */
void finalize_unlock(RESPONSE *response) {
  uart_writeb(CAR_UART, RESP_START);
  uart_write(CAR_UART, (uint8_t *)response, sizeof(RESPONSE));
}