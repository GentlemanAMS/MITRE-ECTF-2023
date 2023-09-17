#include <string.h>
#include "crypto_wrappers.h"
#include "monocypher.h"

// Requires 24 bytes of randomness in the rand_buf
// Ciphertext will be length+CC_ENC_SYM_METADATA_LEN bytes long
// Provides authenticated encryption (any tampering will be detected upon decrypt)
int cc_encrypt_symmetric(uint8_t *ciphertext, uint8_t *plaintext, size_t length, uint8_t *sym_key, uint8_t *rand_buf) {
    memcpy(ciphertext+16, rand_buf, 24);
    crypto_lock(ciphertext+0, ciphertext+40, sym_key, ciphertext+16, plaintext, length);
    return 0;
}

// Plaintext will be length bytes long
// Ciphertext will be length+CC_ENC_SYM_METADATA_LEN bytes long
// Provides authenticated encryption; returns 0 if decrypt succeeds, -1 if tampering or corruption detected
int cc_decrypt_symmetric(uint8_t *plaintext, uint8_t *ciphertext, size_t length, uint8_t *sym_key) {
    return crypto_unlock(plaintext, sym_key, ciphertext+16, ciphertext+0, ciphertext+40, length);
}

// Requires 56 bytes of randomness in the rand_buf
// Ciphertext will be length+72 bytes long
// Provides authenticated encryption (any tampering will be detected upon decrypt)
int cc_encrypt_asymmetric(uint8_t *ciphertext, uint8_t *plaintext, size_t length, uint8_t *rx_pubkey, uint8_t *rand_buf) {
    // Split up the randomness
    uint8_t e_priv[32];
    uint8_t *nonce = rand_buf+32;
    memcpy(e_priv, rand_buf+0, 32);

    // Generate ephemeral key
    uint8_t e_pub[32];
    crypto_x25519_public_key(e_pub, e_priv);

    // Generate raw shared key
    uint8_t raw_shared[32];
    crypto_key_exchange(raw_shared, e_priv, rx_pubkey);

    // Wipe out the ephemeral key
    crypto_wipe(e_priv, 32);

    // Generate shared key by hashing
    uint8_t key_shared[64];
    crypto_blake2b_ctx ctx;
    crypto_blake2b_init(&ctx);
    crypto_blake2b_update(&ctx, raw_shared, 32);
    crypto_blake2b_update(&ctx, e_pub, 32);
    crypto_blake2b_update(&ctx, rx_pubkey, 32);
    crypto_blake2b_update(&ctx, nonce, 24);
    crypto_blake2b_final(&ctx, key_shared);

    memcpy(ciphertext+16, nonce, 24);
    memcpy(ciphertext+40, e_pub, 32);

    crypto_lock(ciphertext+0, ciphertext+72, key_shared, nonce, plaintext, length);
    return 0;
}

// "length" is the length of the plaintext
// Ciphertext should be length+72 bytes long
// Provides authenticated encryption; returns 0 if decrypt succeeds, -1 if tampering or corruption detected
int cc_decrypt_asymmetric(uint8_t *plaintext, uint8_t *ciphertext, size_t length, uint8_t *rx_privkey) {
    // Split up the randomness
    uint8_t *mac = ciphertext+0;
    uint8_t *nonce = ciphertext+16;
    uint8_t *e_pub = ciphertext+40;
    uint8_t *ct = ciphertext+72;

    // Generate internal pub key
    uint8_t rx_pubkey[32];
    crypto_x25519_public_key(rx_pubkey, rx_privkey);

    // Generate raw shared key
    uint8_t raw_shared[32];
    crypto_key_exchange(raw_shared, rx_privkey, e_pub);

    // Generate shared key by hashing
    uint8_t key_shared[64];
    crypto_blake2b_ctx ctx;
    crypto_blake2b_init(&ctx);
    crypto_blake2b_update(&ctx, raw_shared, 32);
    crypto_blake2b_update(&ctx, e_pub, 32);
    crypto_blake2b_update(&ctx, rx_pubkey, 32);
    crypto_blake2b_update(&ctx, nonce, 24);
    crypto_blake2b_final(&ctx, key_shared);

    return crypto_unlock(plaintext, key_shared, nonce, mac, ct, length);
}

// Signature is always 64 bytes
// Privkey is 32 bytes
int cc_sign_asymmetric(uint8_t *signature, uint8_t *message, size_t length, uint8_t *privkey) {
    crypto_sign(signature, privkey, NULL, message, length);

    // wipe signature incase of fault
    uint8_t pub[32];
    crypto_sign_public_key(pub, privkey);
    if (crypto_check(signature, pub, message, length) != 0) {
        for (int i = 0; i < 64; i++) signature[i] = 0xFF;
        return -1;
    }
    return 0;
}

// Signature is expected to be 64 bytes
// Pubkey is 32 bytes
int cc_verify_asymmetric(uint8_t *signature, uint8_t *message, size_t length, uint8_t *pubkey) {
    return crypto_check(signature, pubkey, message, length);
}

// Hash a buffer, return an arbitrary length hash into hash_out; max 64 bytes
// Key can be NULL if unkeyed hash is desired
int cc_hash_internal(uint8_t *hash_out, size_t hash_length, uint8_t *message, uint8_t length, uint8_t *key, uint8_t key_length, size_t iters) {
    if (hash_length > 64) hash_length = 64;
    if (iters < 1) iters = 1;

    uint8_t hash_tmp[64];
    crypto_blake2b_ctx ctx;

    // Hash the initial message
    crypto_blake2b_init(&ctx);
    if (key) crypto_blake2b_update(&ctx, key, key_length);
    crypto_blake2b_update(&ctx, message, length);
    if (key) crypto_blake2b_update(&ctx, key, key_length);
    crypto_blake2b_final(&ctx, hash_tmp);

    if (iters > 1) {
        for (size_t i = 0; i < iters-1; i++) {
            crypto_blake2b_init(&ctx);
            crypto_blake2b_update(&ctx, hash_tmp, 64);
            crypto_blake2b_final(&ctx, hash_tmp);
        }
    }

    memcpy(hash_out, hash_tmp, hash_length);
    return 0;
}

// Standard hash; output CC_HASH_LENGTH bytes
int cc_hash(uint8_t *hash_out, uint8_t *message, uint8_t length) {
    return cc_hash_internal(hash_out, CC_HASH_LEN, message, length, NULL, 0, CC_HASH_ITERS);
}

// Keyed hash; output CC_HASH_LENGTH bytes; expects CC_HASH_KEY_LEN byte-long key
int cc_hash_keyed(uint8_t *hash_out, uint8_t *message, uint8_t length, uint8_t *key) {
    return cc_hash_internal(hash_out, CC_HASH_LEN, message, length, key, CC_HASH_KEY_LEN, CC_HASH_ITERS);
}
