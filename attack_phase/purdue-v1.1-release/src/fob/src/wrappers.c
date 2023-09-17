/**
 * @file wrappers.c
 * @author Purdue eCTF Team
 * @brief Wrapper functions for the fob
 * @date 2023
 * 
 * This file defines wrappers for the fob firmware (encryption, decryption, prng)
 * 
 * @copyright Copyright (c) 2023 Purdue eCTF team
 */

#include <stdbool.h>
#include <stdint.h>

#include "api.h"
#include "board_link.h"
#include "crypto_aead_hash.h"
#include "crypto_auth.h"
#include "driverlib/eeprom.h"
#include "driverlib/rom_map.h"
#include "driverlib/sysctl.h"
#include "eeprom_wrapper.h"
#include "utils/cpu_usage.h"
#include "wrapper.h"

#define WE_DONT_NEED_CRYPTO 1

#define SRAM_XOR_BLOCK 128
#define SEED_MATERIAL_SIZE (SRAM_XOR_BLOCK * 2 + CRYPTO_BYTES)
#define RESEED_SIZE 0x2000

/**
 * @brief Data in the SRAM
 * @note This is a pointer to the data in the SRAM
 * @details This is a pointer to the data in the SRAM
 * 
 */
extern uint32_t _data;

/**
 * @brief Key for HMAC in the PRNG
 * @note This is the key for the PRNG
 * 
 */
uint8_t K[CRYPTO_BYTES] = {0x00};

/**
 * @brief Value for HMAC in the PRNG
 * @note This is the value for the PRNG 
 */
uint8_t V[CRYPTO_BYTES] = {0x01};

/**
 * @brief Counter for reseeding the PRNG
 * @note This is the counter for reseeding the PRNG
 * 
 */
uint32_t reseed_ctr;

/**
 * @brief Flag for whether the PRNG has been seeded
 * @note This is a flag for whether the PRNG has been seeded
 * 
 */
bool prng_seeded = false;

/**
 * @brief Buffer for the PRNG
 */
uint8_t buff[CRYPTO_BYTES * 2 + SEED_MATERIAL_SIZE] = {0};

/**
 * @brief Update the PRNG state
 * 
 * @param data Data to update the PRNG with
 * @param dlen Length of the data
 * @param k Key
 * @param v Value
 *
 * Implemented algorithm : 
 *   K = MAC(K, V || 0x00 || data)
 *   V = MAC(K, V)
 *   if data == NULL:
 *     return (K, V)
 *   K = MAC(K, V || 0x01 || data)
 *   V = MAC(K, V)
 *   return (K, V)
 *  
 */
void prng_update(uint8_t *data, uint64_t dlen, uint8_t *k, uint8_t *v) {
  memcpy(buff, v, CRYPTO_BYTES);
  buff[CRYPTO_BYTES] = 0x00;
  memcpy(buff + CRYPTO_BYTES + 1, data, dlen);

  crypto_auth(k, buff, CRYPTO_BYTES + 1 + dlen, k);
  crypto_auth(v, v, CRYPTO_BYTES, k);

  if (!data)
    return;

  memcpy(buff, v, CRYPTO_BYTES);
  buff[CRYPTO_BYTES] = 0x01;
  memcpy(buff + CRYPTO_BYTES + 1, data, dlen);

  crypto_auth(k, buff, CRYPTO_BYTES + 1 + dlen, k);
  crypto_auth(v, v, CRYPTO_BYTES, k);
}

/**
 * @brief Reseed the PRNG
 * 
 * @param data Data to update the PRNG with
 */
void rand(uint8_t *buf) {

  // Add some sources of entropy to generate a seed
  uint32_t input[3] = {0};
  input[0] = CPUUsageTick();
  input[1] = reseed_ctr;
  input[2] = SysCtlClockGet();

  // Create a hmac from the seed material
  prng_update((uint8_t *)&input, 12, K, V);
  crypto_auth(V, V, CRYPTO_BYTES, K);
  memcpy(buf, V, CRYPTO_BYTES);
  
  prng_update((uint8_t *)&input, 12, K, V);
  if (!(reseed_ctr++ % RESEED_SIZE)) {
    prng_reseed();
  }
}

/**
 * @brief Initialize the PRNG
 * 
 */
void prng_init() {
  // get seed material
  uint8_t seed_material[SEED_MATERIAL_SIZE] = {0};
  for (int i = 0; i < 0x4000; i++) {
    seed_material[(i % SRAM_XOR_BLOCK)] ^= ((uint8_t *)(&_data))[i];
    seed_material[(i % SRAM_XOR_BLOCK) + SRAM_XOR_BLOCK] ^=
        ((uint8_t *)(&_data + 0x1000))[i];
  }
  read_eeprom((void *)(seed_material + 2 * SRAM_XOR_BLOCK), RANDOM_SEED,
              RANDOM_SEED_LEN);
  uint8_t seed_hash[32] = {0};

  // Initialize the PRNG
  crypto_hash(seed_hash, seed_material, SEED_MATERIAL_SIZE);
  prng_update(seed_hash, 32, K, V);
  reseed_ctr = RESEED_SIZE - 1;
  write_eeprom((void *)K, RANDOM_SEED, RANDOM_SEED_LEN);

  // Initialize cpu usage
  CPUUsageInit(MAP_SysCtlClockGet(), 100, 2);
}

/**
 * @brief Reseed the PRNG
 * 
 */
void prng_reseed() {
  uint32_t input[3] = {0};
  input[0] = CPUUsageTick();
  input[1] = reseed_ctr;
  input[2] = SysCtlClockGet();
  uint8_t hash[32] = {0};
  hash_string(hash, (void *)&input, 12);
  prng_update(hash, 32, K, V);
}

/**
 * @brief Seed the PRNG
 * 
 */
void srand() {
  if (!prng_seeded) {
    prng_init();
    prng_seeded = true;
  } else {
    prng_reseed();
  }
}

/**
 * @brief Encrypt a string
 * 
 * @param cipher Buffer to store the ciphertext
 * @param plaintext Plaintext to encrypt
 * @param len Length of the plaintext
 * @param key Key to encrypt with
 * @return uint32_t Length of the ciphertext
 */
uint32_t encrypt_string(uint8_t *cipher, uint8_t *plaintext, uint32_t len,
                        uint8_t *key) {
  uint32_t c_len = 0;
  uint8_t nonce[20] = {0};
  rand(nonce);
  uint8_t ad[8] = {0};

  if (crypto_aead_encrypt(cipher, &c_len, plaintext, len, ad, 8, NULL, nonce,
                          key)) {
    return 0;
  }

  uint32_t l_len = c_len;
  memcpy(cipher + l_len, nonce, CRYPTO_BYTES);
  return l_len + CRYPTO_ABYTES;
}

/**
 * @brief Decrypt a string
 * 
 * @param plaintext Buffer to store the plaintext
 * @param cipher Ciphertext to decrypt
 * @param len Length of the ciphertext
 * @param key Key to decrypt with
 * @return uint32_t Length of the plaintext
 */
uint32_t decrypt_string(uint8_t *plaintext, uint8_t *cipher, uint32_t len,
                        uint8_t *key) {
  uint32_t m_len = 0;
  uint8_t ad[8] = {0};
  if (crypto_aead_decrypt(plaintext, &m_len, NULL, cipher, len - CRYPTO_ABYTES,
                          ad, 8, cipher + len - CRYPTO_ABYTES, key)) {
    return 0;
  }
  return m_len;
}

/**
 * @brief Hash a string
 * 
 * @param hash Buffer to store the hash
 * @param plaintext Plaintext to hash
 * @param len Length of the plaintext
 * @return uint32_t Length of the hash
 */
uint32_t hash_string(uint8_t *hash, uint8_t *plaintext, uint32_t len) {
  crypto_hash(hash, plaintext, len);
  return 32;
}

/**
 * @brief Write to the EEPROM
 * 
 * @note The EEPROM can only be written to in 4 byte chunks
 * @param data Data to write
 * @param addr Address to write to
 * @param len Length of the data
 * @return uint32_t 0 on success
 */
uint32_t write_eeprom(uint8_t *data, uint32_t addr, uint32_t len) {
  if (len % 4 == 0)
    return EEPROMProgram((uint32_t *)data, addr, len);

  uint32_t _len = len + 4 - (len % 4);
  uint8_t _data[_len];
  memcpy(_data, data, len);
  memset(_data + len, 0, _len - len);
  uint32_t _ret = EEPROMProgram((uint32_t *)_data, addr, _len);
  memset(_data, 0, _len);
  return _ret;
}

/**
 * @brief Read from the EEPROM
 * 
 * @note The EEPROM can only be read in 4 byte chunks
 * @param data Buffer to store the data
 * @param addr Address to read from
 * @param len Length of the data
 */
void read_eeprom(uint8_t *data, uint32_t addr, uint32_t len) {
  if (len % 4 == 0) {
    EEPROMRead((uint32_t *)data, addr, len);
    return;
  }

  uint32_t _len = len + 4 - (len % 4);
  uint8_t _data[_len];
  EEPROMRead((uint32_t *)_data, addr, _len);
  memcpy(data, _data, len);
  memset(_data, 0, _len);
}
