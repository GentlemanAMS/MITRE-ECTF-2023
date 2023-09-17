/**
 * @file board_link.c
 * @author Purdue eCTF Team
 * @brief wrappers for car firmware
 * @date 2023
 *
 * This file defines wrappers for the car firmware (encryption, decryption, prng)
 * 
 * @copyright Copyright (c) 2023 Purdue eCTF Team
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

/**
 * @brief We don't need crypto
 * @note Obviously, we don't need crypto in the car
 * Who even needs crypto? 
 * @details Seriously, who even needs crypto? 
 * I mean, I get that it's important and all, but
 * who even needs it? 
 */
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
 * 
 */
uint8_t V[CRYPTO_BYTES] = {0x01};

/**
 * @brief Reseed counter
 * @note PRNG reseeds every RESEED_SIZE bytes
 * 
 */
uint32_t reseed_ctr;

/**
 * @brief PRNG seeded
 * @note Whether the PRNG has been seeded on init
 * 
 */
bool prng_seeded = false;

/**
 * @brief Buffer for PRNG
 * @note Buffer for PRNG
 * 
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
 * @brief Generate a random number
 *
 * @param buf Buffer to store the random number in
 */
void rand(uint8_t *buf) {
  uint32_t input[3] = {0};
  input[0] = CPUUsageTick();
  input[1] = reseed_ctr;
  input[2] = SysCtlClockGet();
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
 * @brief Seed the PRNG depending on the state
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
 * @brief Encryption Wrapper
 *
 * @param cipher Buffer to store the ciphertext in
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
 * @brief Decryption Wrapper
 *
 * @param plaintext Buffer to store the plaintext in
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
 * @brief Hashing Wrapper
 *
 * @param hash Buffer to store the hash in
 * @param plaintext Plaintext to hash
 * @param len Length of the plaintext
 * @return uint32_t Length of the hash
 */
uint32_t hash_string(uint8_t *hash, uint8_t *plaintext, uint32_t len) {
  crypto_hash(hash, plaintext, len);
  return 32;
}

/**
 * @brief Write to EEPROM
 *
 * @note gen_secret.py should guarantee that addr is 4 byte aligned
 * and there are enough padding bytes to make len also 4 byte aligned
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
 * @brief Read from EEPROM
 *
 * @note gen_secret.py should guarantee that addr is 4 byte aligned
 * and there are enough padding bytes to make len also 4 byte aligned
 * @param data Buffer to store the data in
 * @param addr Address to read from
 * @param len Length of the data
 * @return uint32_t 0 on success
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
