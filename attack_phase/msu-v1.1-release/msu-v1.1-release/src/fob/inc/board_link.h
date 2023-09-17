/**
 * @file board_link.h
 * @author Spartan State Security Team
 * @brief File that defines interface for communication between boards
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

#define UNLOCK_MAGIC 0x56

#define BOARD_UART ((uint32_t)UART1_BASE)
#define CAR_UART BOARD_UART
#define PFOB_UART BOARD_UART
#define UFOB_UART BOARD_UART

// Setup Functions
void setup_board_link(void);

// Communications Functions
void request_unlock(void);
void get_challenge(CHALLENGE *challenge);
void finalize_unlock(RESPONSE *response);

#endif
