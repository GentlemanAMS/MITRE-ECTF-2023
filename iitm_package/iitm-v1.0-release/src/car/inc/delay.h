#ifndef DELAY_H
#define DELAY_H

#include <stdbool.h>
#include <stdint.h>


/**
 * @brief 
 * Random Microsecond delay:
 * Executes 10 instructions or less
 */
void random_micro_delay(void);

/**
 * @brief 
 * Random couple of microseconds delay:
 * Executes 90 instructions or less
 */
void random_mini_delay(void);


/**
 * @brief 
 * Random 100s of Microseconds delay:
 * Executes 750 instructions or less
 */
void random_small_delay(void);

/**
 * @brief 
 * Random Millisecond delay:
 * Executes 3000 instructions or less
 */
void random_large_delay(void);

/**
 * @brief
 * Large delay for potential threats 
*/
void large_delay(void);

#endif