#include <stdbool.h>
#include <stdint.h>
#include "driverlib/sysctl.h"

#include "random.h"
#include "delay.h"
#include "time.h"

/**
 * @brief 
 * Random Microsecond delay:
 * Executes 10 instructions or less
 */
inline __attribute__((__always_inline__)) void random_micro_delay(void)
{
    SysCtlDelay((uint32_t)(random_number() & 0x03) + 1);
}

/**
 * @brief 
 * Random couple of microseconds delay:
 * Executes 90 instructions or less
 */
inline __attribute__((__always_inline__)) void random_mini_delay(void)
{
    SysCtlDelay((uint32_t)(random_number() & 0x1F) + 1);
}

/**
 * @brief 
 * Random 100s of Microseconds delay:
 * Executes 750 instructions or less
 */
inline __attribute__((__always_inline__)) void random_small_delay(void)
{
    SysCtlDelay((uint32_t)(random_number() & 0xFF) + 1);
}

/**
 * @brief 
 * Random Millisecond delay:
 * Executes 3000 instructions or less
 */
inline __attribute__((__always_inline__)) void random_large_delay(void)
{
    SysCtlDelay((uint32_t)(random_number() & 0x03FF) + 1);
}

/**
 * @brief
 * Large delay for potential threats 
 * 4000 milliseconds delay
*/
inline __attribute__((always_inline)) void large_delay(void)
{
    uint32_t start_time = millis();
    while(millis() - start_time <= 4000)
        SysCtlDelay(1);
}