/**
 * @file timer_config.h
 * @brief Common library for setting up timeouts across fob/car
 * @date 2023
 */

#ifndef TIMER_CONFIG_H
#define TIMER_CONFIG_H

/** 
 *  @brief Time-out after an attack for max of 4.8 seconds
 *  This function will also stop the timer.
 */
void attacked_stall();

/** 
 *  @brief Time-out after an attack for max of 0.8 seconds
 *  This function will also stop the timer.
 */
void normal_stall();

/**
 * @brief Prime the timer delay to count up. Must be called before any stall.
 */
void prime_delay_timer();

/**
 * @brief Initalize timer functions. Must be called once in main of program.
 * @return 0 on success, != 0 on an error
 */
int init_timers();

#endif // TIMER_CONFIG_H
