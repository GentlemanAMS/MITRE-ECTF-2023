/**
 * @file uart.c
 * @author Spartan State Security Team
 * @brief Firmware UART interface implementation.
 * @date 2023
 *
 * This source file is part of our designed system
 * for MITRE's 2023 Embedded System CTF (eCTF).
 */

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "driverlib/fpu.h"
#include "driverlib/gpio.h"
#include "driverlib/pin_map.h"
#include "driverlib/sysctl.h"
#include "driverlib/uart.h"
#include "inc/hw_memmap.h"
#include "inc/hw_types.h"
#include "inc/hw_uart.h"

#include "uart.h"
#include "firmware.h"

/**
 * @brief Initialize the Host UART interface.
 *
 * UART 0 is used to communicate with the host computer.
 */
void uart_init(void) {
  SysCtlPeripheralEnable(SYSCTL_PERIPH_UART0); // UART 0 for host interface
  SysCtlPeripheralEnable(SYSCTL_PERIPH_GPIOA); // UART 0 is on GPIO Port A
  
  GPIOPinConfigure(GPIO_PA0_U0RX);
  GPIOPinConfigure(GPIO_PA1_U0TX);
  
  GPIOPinTypeUART(GPIO_PORTA_BASE, GPIO_PIN_0 | GPIO_PIN_1);

  // Configure the UART for 115,200, 8-N-1 operation.
  UARTConfigSetExpClk(
      UART0_BASE, SPEED, BAUD,
      (UART_CONFIG_WLEN_8 | UART_CONFIG_STOP_ONE | UART_CONFIG_PAR_NONE));
}

/**
 * @brief Check if there are characters available on a UART interface.
 *
 * @param uart is the base address of the UART port.
 * @return true if there is data available.
 * @return false if there is no data available.
 */
bool uart_avail(uint32_t uart) { return UARTCharsAvail(uart); }

/**
 * @brief Read a byte from a UART interface.
 *
 * @param uart is the base address of the UART port to read from.
 * @return the character read from the interface.
 */
int32_t uart_readb(uint32_t uart) { return UARTCharGet(uart); }

/**
 * @brief Read a sequence of bytes from a UART interface.
 *
 * @param uart is the base address of the UART port to read from.
 * @param buf is a pointer to the destination for the received data.
 * @param n is the number of bytes to read.
 * @return the number of bytes read from the UART interface.
 */
uint32_t uart_read(uint32_t uart, uint8_t *buf, uint32_t n) {
  uint32_t read;

  for (read = 0; read < n; read++) {
    buf[read] = (uint8_t)uart_readb(uart);
  }
  return read;
}

/**
 * @brief Write a byte to a UART interface.
 *
 * @param uart is the base address of the UART port to write to.
 * @param data is the byte value to write.
 */
void uart_writeb(uint32_t uart, uint8_t data) { UARTCharPut(uart, data); }

/**
 * @brief Write a sequence of bytes to a UART interface.
 * Delays a short time so as not to fill any UART FIFO.
 *
 * @param uart is the base address of the UART port to write to.
 * @param buf is a pointer to the data to send.
 * @param len is the number of bytes to send.
 * @return the number of bytes written.
 */
uint32_t uart_write(uint32_t uart, uint8_t *buf, uint32_t len) {
  uint32_t i;

  for (i = 0; i < len; i++) {
    SysCtlDelay(SPEED/BAUD);
    uart_writeb(uart, buf[i]);
  }

  return i;
}
