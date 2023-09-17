#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#define NONCELEN 16
#define KEYLEN 16
#define ASSOCIATED_TAG_LEN 16

#define ARRAYLEN 512
#include "driverlib/sysctl.h"
#include "driverlib/systick.h"

#include "random.h"
#include "time.h"

/**
 * @brief 
 * Must be completely random - Not predictable
 */
volatile uint32_t arr[512] __attribute__((section (".noinit")));

#include "secrets.h"

/**
 * @brief 
 * Creates a seed for srand()
 * @return uint32_t seed
 */
uint32_t random_seed_generator(void)
{
    uint8_t plain_seed[4] = {0,0,0,0};
    for (uint32_t i = 0; i < ARRAYLEN-(4); i=i+4)
    {
        plain_seed[0] = plain_seed[0] ^ arr[i];
        plain_seed[1] = plain_seed[1] ^ arr[i+1];
        plain_seed[2] = plain_seed[2] ^ arr[i+2];
        plain_seed[3] = plain_seed[3] ^ arr[i+3];
    }
    plain_seed[0] = plain_seed[0] ^ random_seed_constant[0];
    plain_seed[1] = plain_seed[1] ^ random_seed_constant[1];
    plain_seed[2] = plain_seed[2] ^ random_seed_constant[2];
    plain_seed[3] = plain_seed[3] ^ random_seed_constant[3];
    uint32_t seed = ((uint32_t)plain_seed[0] << 24) | ((uint32_t)plain_seed[1] << 16) | ((uint32_t)plain_seed[2] << 8) | ((uint32_t)plain_seed[3]);
    return seed; 
}

/**
 * @brief 
 * Returns random value
 * Seed given by srand()
 * @return uint32_t random value
 */
inline __attribute__((__always_inline__)) uint32_t random_number(void)
{
    return (rand() ^ SysTickValueGet() ^ (millis() << 16));
}

