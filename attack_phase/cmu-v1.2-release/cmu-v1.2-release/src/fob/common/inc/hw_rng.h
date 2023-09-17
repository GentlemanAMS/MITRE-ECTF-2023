/**
 * @file hw_rng.h
 * @author Eliana Cohen
 * @date 2023

 * 
 */

#ifndef HW_RNG_H
#define HW_RNG_H

#include <stdbool.h>
#include <stdint.h>

/* ------- Parameters that alter random gen behavior ------------------ */


#define HASH_RESEED_KEY (1)


#define ADC_WHITENING (1)

/* Block size of Key*/
#define HASH_BLOCK_SIZE_64 (64)

/* -------------------- Function Declarations ------------------------- */

/**
 * @brief Initializes the RNG with a on-flash generated key
 * Also, initializes ADC as the entropy source.
 * 
 * NOTE - CALLER MUST ALLOW MEMORY TO BE USED FOR ALL FOLLOWING
 * generateRNGBytes CALLS! MEMORY IS ASSUMED ALLOCATED BY FCNS.
 * 
 * KEYS MUST BE 64 BYTES!
 * @param key Caller-allocated 64-byte key to use for hashing
 * @return 0 on success, -1 on error
 */
int generateRNGInit(uint8_t *key);

/**
 * @brief Generates num_bytes rand values into output
 * 
 * NOTE - output must be a 64 byte array
 * 
 * @param output Output buffer of 64 random bytes
 * @return 0 on success, -1 on error
 */
int generateRNGBytes64(uint8_t *output);


/*** -------------------- Testing functions -------------------- *****/
/**
 * 
 * 
 * 
 * @param entropy_buf an empty array pointer of uint8_ts of size entropySize
 * @param entropy_size the size of the buffer of uint8_t random nums
 * @return 0 on success, -1 on error
 */
int fillEntropyBuf(volatile uint8_t *entropy_buf, uint32_t entropy_size);




#endif // HW_RNG_H
