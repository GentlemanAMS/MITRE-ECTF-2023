/*
Provides a wrapper for uart and eeprom access. Maybe should be called communication.h? (theres anyways already a uart.h in tivaware)
*/


#ifndef UART_H
#define UART_H


#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "util.h"

//#define DEVICE_UART ((uint32_t)UART1_BASE)
#define DEVICE_UART ((uint32_t)UART1_BASE)
#define HOST_UART ((uint32_t)UART0_BASE)

/**********************************************
    quick fix for annoying vscode linting error
**********************************************/
#ifndef GPIO_PB0_U1RX
#define GPIO_PB0_U1RX 0x00010001
#endif

#ifndef GPIO_PB1_U1TX
#define GPIO_PB1_U1TX 0x00010401
#endif

#ifndef GPIO_PA0_U0RX
#define GPIO_PA0_U0RX 0x00000001
#endif

#ifndef GPIO_PA1_U0TX
#define GPIO_PA1_U0TX 0x00000401
#endif

/*********************************************/

static const uint8_t uart_magic[] = "0ops"; //magic for sending packet

//currently unused; just using a for loop
#define UART_SEND_LONG(PORT, data) {\
            UARTCharPut(PORT, (uint8_t)(data >> 0));\
            UARTCharPut(PORT, (uint8_t)(data >> 8));\
            UARTCharPut(PORT, (uint8_t)(data >> 16));\
            UARTCharPut(PORT, (uint8_t)(data >> 24));\
            UARTCharPut(PORT, (uint8_t)(data >> 32));\
            UARTCharPut(PORT, (uint8_t)(data >> 40));\
            UARTCharPut(PORT, (uint8_t)(data >> 48));\
            UARTCharPut(PORT, (uint8_t)(data >> 56));\
            }

//initialize UART
void uart_init(void);

//send a message packet through the UART interface. uart_init() must be called first
void uart_send_message(const uint32_t PORT, Message* message);

//send raw packet through UART interface. uart_init() must be called first
void uart_send_raw(const uint32_t PORT, void* message, size_t size);

//read raw packet through UART interface. uart_init() must be called first
void uart_read_raw(const uint32_t PORT, void* message, size_t size);

bool uart_read_message(const uint32_t PORT, Message* message);

//initialize EEPROM
void eeprom_init(void);

//write message to an address in the eeprom
void eeprom_read(void* msg, size_t len, size_t address);

//read a value from eeprom
void eeprom_write(void* msg, size_t len, size_t address);


#endif