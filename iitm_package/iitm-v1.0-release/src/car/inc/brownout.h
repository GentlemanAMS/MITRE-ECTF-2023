#ifndef BROWNOUT_H
#define BROWNOUT_H

#include <stdbool.h>
#include <stdint.h>

/**
 * @brief Set the brownout protection object
 * Brown Out Protections
 * 
 * System Control Reset when tampering is observed 
 */
void set_brownout_protection(void);

/**
 * @brief 
 * Cause interrupt which in turn resets device
 */
void brownout_interrupt(void);
#endif