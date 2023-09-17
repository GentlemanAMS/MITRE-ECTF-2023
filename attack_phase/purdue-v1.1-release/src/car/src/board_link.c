/**
 * @file board_link.c
 * @author Purdue eCTF Team
 * @brief File that contains the board link functions
 * @date 2023
 *
 * @copyright Copyright (c) 2023 Purdue eCTF Team
 */

#include <stdbool.h>
#include <stdint.h>

#include "inc/hw_memmap.h"
#include "inc/hw_types.h"
#include "inc/hw_uart.h"

#include "driverlib/fpu.h"
#include "driverlib/gpio.h"
#include "driverlib/pin_map.h"
#include "driverlib/sysctl.h"
#include "driverlib/uart.h"

#include "board_link.h"
#include "eeprom_wrapper.h"

#ifdef CDEBUG
#include "ustdlib.h"
#endif

/**
 * @brief Configure the UART peripherals used for communication
 *
 * UART 1 is used to communicate between boards
 * UART 0 is used to communicate with the host
 *
 */
void setup_comms(void) {
  // Configure the UART peripherals used in this example
  // RCGC   Run Mode Clock Gating
  SysCtlPeripheralEnable(SYSCTL_PERIPH_UART0); // UART 0 for host interface
  SysCtlPeripheralEnable(SYSCTL_PERIPH_GPIOA); // UART 0 is on GPIO Port A
  // HBCTL  High-performance Bus Control
  // PCTL   Port Control
  GPIOPinConfigure(GPIO_PA0_U0RX);
  GPIOPinConfigure(GPIO_PA1_U0TX);
  // DIR    Direction
  // AFSEL  Alternate Function Select
  // DR2R   2-mA Drive Select
  // DR4R   4-mA Drive Select
  // DR8R   8-mA Drive Select
  // SLR    Slew Rate Control Select
  // ODR    Open Drain Select
  // PUR    Pull-Up Select
  // PDR    Pull-Down Select
  // DEN    Digital Enable
  // AMSEL  Analog Mode Select
  GPIOPinTypeUART(GPIO_PORTA_BASE, GPIO_PIN_0 | GPIO_PIN_1);

  // Configure the UART for 115,200, 8-N-1 operation.
  UARTConfigSetExpClk(
      UART0_BASE, SysCtlClockGet(), 115200,
      (UART_CONFIG_WLEN_8 | UART_CONFIG_STOP_ONE | UART_CONFIG_PAR_NONE));
  UARTFIFOLevelSet(UART0_BASE, UART_FIFO_TX4_8, UART_FIFO_RX4_8);

  SysCtlPeripheralEnable(SYSCTL_PERIPH_UART1);
  SysCtlPeripheralEnable(SYSCTL_PERIPH_GPIOB);

  GPIOPinConfigure(GPIO_PB0_U1RX);
  GPIOPinConfigure(GPIO_PB1_U1TX);

  GPIOPinTypeUART(GPIO_PORTB_BASE, GPIO_PIN_0 | GPIO_PIN_1);

  // Configure the UART for 115,200, 8-N-1 operation.
  UARTConfigSetExpClk(
      BOARD_UART, SysCtlClockGet(), 115200,
      (UART_CONFIG_WLEN_8 | UART_CONFIG_STOP_ONE | UART_CONFIG_PAR_NONE));
  UARTFIFOLevelSet(BOARD_UART, UART_FIFO_TX4_8, UART_FIFO_RX4_8);

  // Sometimes there are null characters in the UART buffer, so we clear it
  while (UARTCharsAvail(BOARD_UART)) {
    UARTCharGet(BOARD_UART);
  }
}

#ifdef CDEBUG
/**
 * @brief Send a message to the host
 *
 * @param uart_p The UART peripheral to use
 * @param message The message to send
 * @param len The length of the message
 *
 * @return The length of the message
 *
 * @note This function is only used for debugging purposes
 */
uint32_t debug_send_message(uint32_t uart_p, char *message, int len) {
  UARTCharPut(uart_p, HOST_MESSAGE_HDR);
  UARTCharPut(uart_p, len & 0xFF);
  for (int i = 0; i < (len & 0xFF); i++) {
    UARTCharPut(uart_p, message[i]);
  }
  return len;
}

/**
 * @brief Send an integer to the host as a value
 *
 * @param uart_p The UART peripheral to use
 * @param value The integer to send
 *
 * @return The length of the message
 *
 * @note This function is only used for debugging purposes
 */
uint32_t debug_send_int(uint32_t uart_p, uint32_t value) {
  char buffer[10];
  int len = usprintf(buffer, "%d", value);

  UARTCharPut(uart_p, HOST_MESSAGE_HDR);
  UARTCharPut(uart_p, len & 0xFF);
  for (int i = 0; i < (len & 0xFF); i++) {
    UARTCharPut(uart_p, buffer[i]);
  }
  return len;
}

/**
 * @brief Send an array to the host
 *
 * @param uart_p The UART peripheral to use
 * @param array The array to send
 * @param len The length of the array
 *
 * @return The length of the message
 *
 * @note This function is only used for debugging purposes
 * the tools, will interpret the message as a array and display it in hex
 */
uint32_t debug_send_array(uint32_t uart_p, uint8_t *array, uint32_t len) {
  UARTCharPut(uart_p, UNLOCK_HDR);
  UARTCharPut(uart_p, len & 0xFF);
  for (int i = 0; i < (len & 0xFF); i++) {
    UARTCharPut(uart_p, array[i]);
  }
  return len;
}
#endif

/**
 * @brief Delay for a specified number of milliseconds
 *
 * @param ms The number of milliseconds to delay
 *
 * @note We use SysCtlDelay() to delay for a specified number of milliseconds
 */
void delay_ms(uint32_t ms) {

  // 1 clock cycle = 1 / SysCtlClockGet() second
  // 1 SysCtlDelay = 3 clock cycle = 3 / SysCtlClockGet() second
  // 1 second = SysCtlClockGet() / 3
  // 0.001 second = 1 ms = SysCtlClockGet() / 3 / 1000

  SysCtlDelay((SysCtlClockGet() / 3) * ms / 1000);
}

/**
 * @brief receive a message from the board of a specific header
 *
 * @param uart_p the uart peripheral to use
 * @param message the message to fill
 * @param type the type of message to wait for
 *
 * @return the length of the message
 *
 * @note this function will block until the message is received
 */
uint8_t receive_message_by_type(uint32_t uart_p, MESSAGE_PACKET *message,
                                uint8_t type) {
  do {
    receive_message(uart_p, message);
  } while (message->header != type);

  return message->message_len;
}

/**
 * @brief check if there are any characters in a specified uart fifo
 *
 * @param uart_p the uart peripheral to use
 *
 * @return true if there are characters in the fifo
 *
 * @note this function will not block, it will return immediately
 */
bool has_message(uint32_t uart_p) { return UARTCharsAvail(uart_p); }

/**
 * @brief receive a message from the board
 *
 * @param uart_p the uart peripheral to use
 * @param message the message to fill
 *
 * @return the length of the message
 *
 * @note this function will block until the message is received
 * and the message needs to have a valid header
 *
 */
uint8_t receive_message(uint32_t uart_p, MESSAGE_PACKET *message) {
  while (true) {
#ifdef CDEBUG
    debug_send_message(HOST_UART, "CAR: Waiting for message", 24);
#endif
    message->header = (uint8_t)UARTCharGet(uart_p);
    switch (message->header) {
    case UNLOCK_HDR:
    case UNLOCK_RES_HDR:
    case START_HDR:
    case ACK_HDR:
#ifdef CDEBUG
      debug_send_message(HOST_UART, "CAR: Got header:", 16);
      debug_send_int(HOST_UART, (uint32_t)message->header);
      debug_send_message(HOST_UART, "\n", 1);
#endif
      break;
    default:
#ifdef CDEBUG
      debug_send_message(HOST_UART, "CAR: Invalid header : ", 22);
      debug_send_int(HOST_UART, (uint32_t)message->header);
      debug_send_message(HOST_UART, "\n", 1);
#endif
      continue;
    }
    break;
  }

  message->message_len = (uint8_t)UARTCharGet(uart_p);

  if (message->message_len > MESSAGE_BUFFER_MAX) {
    message->message_len = MESSAGE_BUFFER_MAX;
  }

  for (int i = 0; i < message->message_len; i++) {
    message->buffer[i] = (uint8_t)UARTCharGet(uart_p);
  }

  for (int i = message->message_len; i < MESSAGE_BUFFER_MAX; i++) {
    UARTCharGet(uart_p);
  }

  return message->message_len;
}

/**
 * @brief Send a message to the specified UART peripheral
 *
 * @param uart_p The UART peripheral to use
 * @param message The message to send
 *
 * @return uint32_t The length of the message sent
 *
 * @note This function will block until the message is sent
 * This is because the UARTCharPut() function will block until there is space in
 * the FIFO
 */
uint32_t send_message(uint32_t uart_p, MESSAGE_PACKET *message) {
  UARTCharPut(uart_p, message->header);
  UARTCharPut(uart_p, message->message_len);

  if (message->message_len > MESSAGE_BUFFER_MAX) {
    message->message_len = MESSAGE_BUFFER_MAX;
  }

  for (int i = 0; i < message->message_len; i++) {
    UARTCharPut(uart_p, message->buffer[i]);
    delay_ms(1);
  }

  for (int i = message->message_len; i < MESSAGE_BUFFER_MAX; i++) {
    UARTCharPut(uart_p, 0);
    delay_ms(1);
  }

  return message->message_len;
}
