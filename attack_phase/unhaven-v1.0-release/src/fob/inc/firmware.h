/**
 * A header file defining common variables for the sensor
 */

#ifndef FIRMWARE_H
#define FIRMWARE_H

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

typedef enum {
  COMMAND_STATE_RESET = 0,
  COMMAND_STATE_WAITING_FOR_PAIRED_ECDH,
  COMMAND_STATE_WAITING_FOR_CAR_ECDH,
  COMMAND_STATE_WAITING_FOR_SECRET,
  COMMAND_STATE_IN_PAIRING_MODE,
}COMMAND_STATE_e;

extern COMMAND_STATE_e message_state;

void process_host_uart(void);
void process_board_uart(void);
// uint8_t get_if_paired(void);

#endif
