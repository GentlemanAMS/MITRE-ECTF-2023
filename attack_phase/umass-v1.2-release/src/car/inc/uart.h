/**
 * @file uart.h
 * @author Kyle Scaplen
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

#ifndef UART_H
#define UART_H

#include <stdbool.h>
#include <stdint.h>

#include "inc/hw_memmap.h"

#define HOST_UART ((uint32_t)UART0_BASE)

/**
 * @brief Initialize the UART interfaces.
 *
 * UART 0 is used to communicate with the door/fob.
 */
void uart_init(void);

#endif // UART_H
