/**
 * @file board_link.h
 * @author Spartan State Security Team
 * @brief Function that defines interface for communication between boards
 * @date 2023
 *
 * This source file is part of our designed system
 * for MITRE's 2023 Embedded System CTF (eCTF).
 */

#ifndef BOARD_LINK_H
#define BOARD_LINK_H

#include <stdint.h>

#include "inc/hw_memmap.h"
#include "firmware.h"
#include "uart.h"

#define UNLOCK_MAGIC 0x56
#define CHAL_START 0x57
#define RESP_START 0x58

#define FOB_UART ((uint32_t)UART1_BASE)

// Setup Functions
void setup_board_link(void);

// Communications Functions
bool send_challenge(CHALLENGE *challenge);
bool fob_requests_unlock(void);

// Advanced Communications Functions
bool get_response(RESPONSE *response);

#endif
