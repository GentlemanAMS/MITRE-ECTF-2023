/**
 * @file wrapper.h
 * @author Purdue eCTF Team
 * @brief Header file for wrappers.c
 * @date 2023
 *
 * @copyright Copyright (c) 2023 Purdue eCTF Team
 */

#ifndef WRAPPER_H
#define WRAPPER_H

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>

// header for wrappers prng functions
void prng_update(uint8_t *data, uint64_t dlen, uint8_t *k, uint8_t *v);
void rand(uint8_t *buf);
void prng_init();
void prng_reseed();
void srand();

// header for wrappers cryptographic primitives functions
uint32_t encrypt_string(uint8_t *cipher, uint8_t *plaintext, uint32_t len,
                        uint8_t *key);
uint32_t decrypt_string(uint8_t *plaintext, uint8_t *cipher, uint32_t len,
                        uint8_t *key);
uint32_t hash_string(uint8_t *hash, uint8_t *plaintext, uint32_t len);

// header for wrappers eeprom functions
uint32_t write_eeprom(uint8_t *data, uint32_t addr, uint32_t len);
void read_eeprom(uint8_t *data, uint32_t addr, uint32_t len);

#endif /* WRAPPER_H */
