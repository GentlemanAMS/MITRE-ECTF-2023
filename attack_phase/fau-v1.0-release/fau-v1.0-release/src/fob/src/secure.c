#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include "random.h"
#include "secure.h"
#include "board_link.h"
#include "firmware.h"
#include "aes.h"

#include "driverlib/eeprom.h"

void generate_seed(void) {
    uint8_t entropy[8] = {0};
    EEPROMRead(entropy, 0, AES_BYTES/2);
    FillEntropy64(entropy);
}

void hash_random(uint8_t * digest) {
    uint8_t random_current[16] = {0};
    uint8_t random_update[16] = {0};

    generate_seed();
    RandomSeed(digest);

    EEPROMRead(random_current, 0, AES_BYTES);

    for (int i = 0; i < 16; i++) {
        random_update[i] = random_current[i] ^ digest[i];
    }

    EEPROMProgram(random_update, 0, AES_BYTES);
}

void hash_message(uint8_t * digest, uint8_t * msg, size_t len) {
    SetEntropyUsing(msg, len);
    RandomSeed(digest);
}

void aes_sharedkey_rx(uint8_t * shared_key_out)
{
    MESSAGE_PACKET message_tx, message_rx;
    struct AES_ctx ctx;
    uint32_t key[4];
    uint8_t buf[256] = {0};

    uint8_t random_tx[AES_BYTES] = {0};
    uint8_t random_rx[AES_BYTES] = {0};
    uint8_t cipher[AES_BYTES] = {0};
    // **********************
    // 1. Setup and init
    // **********************
    // init message_rx
    message_rx.magic = 0;
    message_rx.message_len = 0;
    message_rx.buffer = buf;
    // Generate ephemeral session random
    hash_random(random_tx);
    memcpy(cipher, random_tx, AES_BYTES);
    // Get this device's private key from EEPROM
    EEPROMRead(key, AES_BYTES, AES_BYTES);
    // Initialize context
    AES_init_ctx(&ctx, (uint8_t *)key);

    // **********************
    // 2. Receive random from other device, then decrypt
    // **********************
    receive_board_message_by_type(&message_rx, CIPHER_MAGIC);
    memcpy(random_rx, message_rx.buffer, AES_BYTES);
    AES_ECB_decrypt(&ctx, random_rx);

    // **********************
    // 3. Encrypt this device's random, then send
    // **********************
    message_tx.message_len = AES_BYTES;
    message_tx.magic = CIPHER_MAGIC;
    message_tx.buffer = cipher;
    AES_ECB_encrypt(&ctx, message_tx.buffer);
    send_board_message(&message_tx);

    // **********************
    // 4. Compute shared secret
    // **********************
    for (int i = 0; i < 16; i++) {
        shared_key_out[i] = random_tx[i] ^ random_rx[i];  
    }

}

void aes_sharedkey_tx(uint8_t * shared_key_out, size_t addr)
{
    MESSAGE_PACKET message_tx, message_rx;
    struct AES_ctx ctx;
    uint32_t key[4];
    uint8_t buf[256] = {0};

    uint8_t random_tx[AES_BYTES] = {0};
    uint8_t random_rx[AES_BYTES] = {0};
    uint8_t cipher[AES_BYTES] = {0};
    // **********************
    // 1. Setup and init
    // **********************
    // init message_rx
    message_rx.magic = 0;
    message_rx.message_len = 0;
    message_rx.buffer = buf;
    // Generate ephemeral session random
    hash_random(random_tx);
    memcpy(cipher, random_tx, AES_BYTES);    
    // Get this device's pairing or unlocking private key from EEPROM
    EEPROMRead(key, addr, AES_BYTES);
    // Initialize context
    AES_init_ctx(&ctx, (uint8_t *)key);

    // **********************
    // 2. Encrypt this device's random, then send
    // **********************
    message_tx.message_len = AES_BYTES;
    message_tx.magic = CIPHER_MAGIC;
    message_tx.buffer = cipher;
    // memcpy(message_tx.buffer, random_tx, AES_BYTES);
    AES_ECB_encrypt(&ctx, message_tx.buffer);
    send_board_message(&message_tx);

    // **********************
    // 3. Receive random from other device, then decrypt
    // **********************
    receive_board_message_by_type(&message_rx, CIPHER_MAGIC);
    memcpy(random_rx, message_rx.buffer, AES_BYTES);
    AES_ECB_decrypt(&ctx, random_rx);

    // **********************
    // 4. Compute shared secret
    // **********************
    for (int i = 0; i < 16; i++) {
        shared_key_out[i] = random_tx[i] ^ random_rx[i];  
    }
}

bool aes_unlock_car(uint8_t *unlock_pass, size_t len_pass, uint8_t *shared_key) {
    MESSAGE_PACKET message;
    struct AES_ctx ctx;
    uint8_t pass_hashed[AES_BYTES] = {0};
    uint8_t buf[256] = {0};

    message.message_len = 0;
    message.magic = 0;
    message.buffer = buf;

    // Hash the unlock password to expand from < 16B
    // to exactly 16B
    hash_message(pass_hashed, unlock_pass, len_pass);

    AES_init_ctx(&ctx, shared_key);

    // Receive and decrypt password from fob
    receive_board_message_by_type(&message, CIPHER_MAGIC);
    AES_ECB_decrypt(&ctx, message.buffer);

    // memcmp returns '0' if the comparison is equal
    return !(memcmp(pass_hashed, message.buffer, AES_BYTES));
}

void aes_unlock_fob(uint8_t *unlock_pass, size_t len_pass, uint8_t *shared_key) {
    MESSAGE_PACKET message;
    struct AES_ctx ctx;
    uint8_t buf[256] = {0};

    message.message_len = AES_BYTES;
    message.magic = CIPHER_MAGIC;
    message.buffer = buf;

    // Hash the unlock password to expand from < 16B
    // to exactly 16B
    hash_message(message.buffer, unlock_pass, len_pass);

    AES_init_ctx(&ctx, shared_key);

    // encrypt password and send
    AES_ECB_encrypt(&ctx, message.buffer);
    send_board_message(&message);
}

void aes_pair_unpaired(uint8_t *shared_key) {
    MESSAGE_PACKET message;
    struct AES_ctx ctx;
    uint8_t buf[256] = {0};

    message.message_len = 0;
    message.magic = 0;
    message.buffer = buf;

    AES_init_ctx(&ctx, shared_key);

    // Receive and decrypt key from fob
    receive_board_message_by_type(&message, CIPHER_MAGIC);
    AES_ECB_decrypt(&ctx, message.buffer);

    // Write key to EEPROM
    EEPROMProgram(message.buffer,2*AES_BYTES,AES_BYTES);
}

void aes_pair_paired(uint8_t *shared_key) {
    MESSAGE_PACKET message;
    struct AES_ctx ctx;
    uint32_t key[4];

    // Get this device's pairing private key from EEPROM
    EEPROMRead(key, 2*AES_BYTES, AES_BYTES);

    message.message_len = AES_BYTES;
    message.magic = CIPHER_MAGIC;
    message.buffer = key;

    AES_init_ctx(&ctx, shared_key);

    // encrypt key and send
    AES_ECB_encrypt(&ctx, message.buffer);
    send_board_message(&message);
}
