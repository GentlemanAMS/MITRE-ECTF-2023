/**
 * @file uart.h
 * @author Spartan State Security Team
 * @brief Firmware UART interface implementation.
 * @date 2023
 *
 * This source file is part of our designed system
 * for MITRE's 2023 Embedded System CTF (eCTF).
 */

#ifndef UART_H
#define UART_H

#include <stdbool.h>
#include <stdint.h>

#include "inc/hw_memmap.h"

#define HOST_UART ((uint32_t)UART0_BASE)

// Configuration and Status
void uart_init(void);
bool uart_avail(uint32_t uart);

// Read Functions Rx
int32_t uart_readb(uint32_t uart);
uint32_t uart_read(uint32_t uart, uint8_t *buf, uint32_t n);

// Write Functions Tx
void uart_writeb(uint32_t uart, uint8_t data);
uint32_t uart_write(uint32_t uart, uint8_t *buf, uint32_t len);

#endif // UART_H
