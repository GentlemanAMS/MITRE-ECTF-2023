#include "monocypher.h"

#define CC_HASH_ITERS 16
#define CC_HASH_LEN 32
#define CC_HASH_KEY_LEN 32

#define CC_ENC_SYM_KEY_LEN 32

#define CC_ENC_SYM_METADATA_LEN 40
#define CC_ENC_ASYM_METADATA_LEN 72

// Requires 24 bytes of randomness in the rand_buf
// Ciphertext will be length+CC_ENC_SYM_METADATA_LEN bytes long
// Provides authenticated encryption (any tampering will be detected upon decrypt)
int cc_encrypt_symmetric(uint8_t *ciphertext, uint8_t *plaintext, size_t length, uint8_t *sym_key, uint8_t *rand_buf);

// Plaintext will be length bytes long
// Ciphertext will be length+CC_ENC_SYM_METADATA_LEN bytes long
// Provides authenticated encryption; returns 0 if decrypt succeeds, -1 if tampering or corruption detected
int cc_decrypt_symmetric(uint8_t *plaintext, uint8_t *ciphertext, size_t length, uint8_t *sym_key);

// Requires 56 bytes of randomness in the rand_buf
// Ciphertext will be length+72 bytes long
// Provides authenticated encryption (any tampering will be detected upon decrypt)
int cc_encrypt_asymmetric(uint8_t *ciphertext, uint8_t *plaintext, size_t length, uint8_t *rx_pubkey, uint8_t *rand_buf);

// "length" is the length of the plaintext
// Ciphertext should be length+72 bytes long
// Provides authenticated encryption; returns 0 if decrypt succeeds, -1 if tampering or corruption detected
int cc_decrypt_asymmetric(uint8_t *plaintext, uint8_t *ciphertext, size_t length, uint8_t *rx_privkey);

// Signature is always 64 bytes
// Privkey is 32 bytes
int cc_sign_asymmetric(uint8_t *signature, uint8_t *message, size_t length, uint8_t *privkey);

// Signature is expected to be 64 bytes
// Pubkey is 32 bytes
int cc_verify_asymmetric(uint8_t *signature, uint8_t *message, size_t length, uint8_t *pubkey);

// Hash a buffer, return an arbitrary length hash into hash_out; max 64 bytes
// Key can be NULL if unkeyed hash is desired
int cc_hash_internal(uint8_t *hash_out, size_t hash_length, uint8_t *message, uint8_t length, uint8_t *key, uint8_t key_length, size_t iters);

// Standard hash; output CC_HASH_LENGTH bytes
int cc_hash(uint8_t *hash_out, uint8_t *message, uint8_t length);

// Keyed hash; output CC_HASH_LENGTH bytes; expects CC_HASH_KEY_LEN byte-long key
int cc_hash_keyed(uint8_t *hash_out, uint8_t *message, uint8_t length, uint8_t *key);
