#ifndef __FAUSECURE_H__
#define __FAUSECURE_H__

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <firmware.h>

#define AES_BITS    (128)
#define AES_BYTES   (16)

void generate_seed(void);
void hash_random(uint8_t *digest);
void hash_message(uint8_t * digest, uint8_t * msg, size_t len);
void aes_sharedkey_rx(uint8_t * shared_key_out);
void aes_sharedkey_tx(uint8_t * shared_key_out, size_t addr);
bool aes_unlock_car(uint8_t *unlock_pass, size_t len_pass, uint8_t *shared_key);
void aes_unlock_fob(uint8_t *unlock_pass, size_t len_pass, uint8_t *shared_key);
void aes_pair_unpaired(uint8_t *shared_key);
void aes_pair_paired(uint8_t *shared_key);

#endif