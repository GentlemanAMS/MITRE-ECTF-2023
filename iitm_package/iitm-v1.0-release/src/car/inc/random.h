#ifndef RANDOM_H
#define RANDOM_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include "driverlib/sysctl.h"
#include "driverlib/systick.h"

/**
 * @brief 
 * Returns random value
 * Seed given by srand()
 * @return uint32_t random value
 */
uint32_t random_number(void);

/**
 * @brief 
 * Creates a seed for srand()
 * @return uint32_t seed
 */
uint32_t random_seed_generator(void);

#endif
