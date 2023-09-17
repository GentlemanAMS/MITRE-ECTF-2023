/**
 * @file main.c
 * @author Frederich Stine
 * @brief eCTF Fob Example Design Implementation
 * @date 2023
 *
 * This source file is part of an example system for MITRE's 2023 Embedded
 * System CTF (eCTF). This code is being provided only for educational purposes
 * for the 2023 MITRE eCTF competition, and may not meet MITRE standards for
 * quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2023 The MITRE Corporation
 */

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "inc/hw_ints.h"
#include "inc/hw_memmap.h"

#include "driverlib/eeprom.h"
#include "driverlib/flash.h"
#include "driverlib/gpio.h"
#include "driverlib/interrupt.h"
#include "driverlib/pin_map.h"
#include "driverlib/sysctl.h"
#include "driverlib/timer.h"

#include "secrets.h"

#include "board_link.h"
#include "feature_list.h"
#include "uart.h"
#include "constant.h"
#include "monocypher.h"
#include "entropy.h"

#define FOB_STATE_PTR 0x3FC00
#define FLASH_DATA_SIZE           \
    (sizeof(FLASH_DATA) % 4 == 0) \
        ? sizeof(FLASH_DATA)      \
        : sizeof(FLASH_DATA) + (4 - (sizeof(FLASH_DATA) % 4))
#define FLASH_PAIRED 0x00
#define FLASH_UNPAIRED 0xFF

/*** Structure definitions ***/
// Defines a struct for the format of an enable message
typedef struct ENABLE_PACKET {
    uint8_t nonce[NONCE_LEN];
    uint8_t mac[MAC_LEN];
    uint8_t car_id;
    uint8_t feature;
    uint8_t signature[SIGNATURE_LEN];
} ENABLE_PACKET;

// Defines a struct for the format of a pairing message
typedef struct {
    uint8_t car_id;
    uint8_t pin[7];
    uint8_t pubkey[PUBKEY_LEN];          // paired fob pk (unique per fob)
    uint8_t privkey[KEY_LEN];            // paired fob sk (unique per fob)
    uint8_t link_key[KEY_LEN];           // car-fob secret link key
    uint8_t pubkey_cert[SIGNATURE_LEN];  // paired fob pk signature signed by CA
} PAIR_PACKET;

// Defines a struct for the exchange of public keys for AKE
typedef struct SIG_PK_PACKET {
    uint8_t pubkey[PUBKEY_LEN];
    uint8_t signature[SIGNATURE_LEN];
    uint8_t ake_pk[PUBKEY_LEN];
} SIG_PK_PACKET;

// Defines a struct for pre-authentication verifications
typedef struct PREAUTH_PACKET {
    uint8_t nonce[NONCE_LEN];
    uint8_t mac[MAC_LEN];
    uint8_t ciphertext[2 + SIGNATURE_LEN];
} PREAUTH_PACKET;

// Defines a struct for challenge-response authentication
typedef struct {
    uint8_t nonce[NONCE_LEN];
    uint8_t mac[MAC_LEN];
    uint8_t challenge[KEY_LEN + 6];
} UNLOCK_PACKET;

// Defines a struct simply to hold symmetric crypto information
typedef struct {
    uint8_t nonce[NONCE_LEN];
    uint8_t mac[MAC_LEN];
} SYMMETRIC_DATA;

// Defines a struct for the format of start message
typedef struct FEATURE_DATA {
    uint8_t car_id;
    uint8_t num_active;
    uint8_t features[NUM_FEATURES];
    uint8_t signatures[NUM_FEATURES][SIGNATURE_LEN];
} FEATURE_DATA;

// Defines a struct for storing the state in flash
typedef struct FLASH_DATA {
    uint8_t paired;
    PAIR_PACKET pair_info;
    FEATURE_DATA feature_info;
} FLASH_DATA;

/*** Function definitions ***/
// Core functions - all functionality supported by fob
void saveFobState(FLASH_DATA *flash_data);
void pairFob(FLASH_DATA *fob_state_ram);
void unlockCar(FLASH_DATA *fob_state_ram);
void enableFeature(FLASH_DATA *fob_state_ram);
void startCar(FLASH_DATA *fob_state_ram);

// Helper functions - receive ack message
uint8_t receiveAck();
void sendAckSuccess();
void sendAckFailure();

/**
 * @brief Main function for the fob example
 *
 * Listens over UART and SW1 for an unlock command. If unlock command presented,
 * attempts to unlock door. Listens over UART for pair command. If pair
 * command presented, attempts to either pair a new key, or be paired
 * based on firmware build.
 */
int main(void) {
    FLASH_DATA fob_state_ram;
    FLASH_DATA *fob_state_flash = (FLASH_DATA *)FOB_STATE_PTR;

// If paired fob, initialize the system information
#if PAIRED == 1
    if (fob_state_flash->paired != FLASH_PAIRED) {
        memcpy((void *)(fob_state_ram.pair_info.pin), PAIR_PIN, 6);
        fob_state_ram.pair_info.pin[6] = '\0';
        fob_state_ram.pair_info.car_id = (uint8_t)CAR_ID[0];
        fob_state_ram.feature_info.car_id = (uint8_t)CAR_ID[0];

        // Add secrets to flash, to be copied over to unpaired fob later after
        // pairing
        memcpy((void *)(fob_state_ram.pair_info.pubkey), (void *)PAIRED_FOB_PK,
               PUBKEY_LEN);
        memcpy((void *)(fob_state_ram.pair_info.pubkey_cert),
               (void *)PAIRED_FOB_SIG, SIGNATURE_LEN);
        memcpy((void *)(fob_state_ram.pair_info.privkey), (void *)PAIRED_FOB_SK,
               KEY_LEN);
        memcpy((void *)(fob_state_ram.pair_info.link_key), (void *)CAR_SECRET,
               KEY_LEN);

        fob_state_ram.paired = FLASH_PAIRED;

        saveFobState(&fob_state_ram);
    }
#else
    fob_state_ram.paired = FLASH_UNPAIRED;
#endif

    if (fob_state_flash->paired == FLASH_PAIRED) {
        memcpy(&fob_state_ram, fob_state_flash, FLASH_DATA_SIZE);
    }

    // This will run on first boot to initialize features
    if (fob_state_ram.feature_info.num_active > NUM_FEATURES) {
        fob_state_ram.feature_info.num_active = 0;
        saveFobState(&fob_state_ram);
    }

    // Initialise the RNG
    entropy_init();

    // Initialize UART
    uart_init();

    // Initialize board link UART
    setup_board_link();

    // Setup SW1
    GPIOPinTypeGPIOInput(GPIO_PORTF_BASE, GPIO_PIN_4);
    GPIOPadConfigSet(GPIO_PORTF_BASE, GPIO_PIN_4, GPIO_STRENGTH_4MA,
                     GPIO_PIN_TYPE_STD_WPU);

    // Change LED color: white
    GPIOPinWrite(GPIO_PORTF_BASE, GPIO_PIN_1, GPIO_PIN_1);  // r
    GPIOPinWrite(GPIO_PORTF_BASE, GPIO_PIN_2, GPIO_PIN_2);  // b
    GPIOPinWrite(GPIO_PORTF_BASE, GPIO_PIN_3, GPIO_PIN_3);  // g

    // Declare a buffer for reading and writing to UART
    uint8_t uart_buffer[10];
    uint8_t uart_buffer_index = 0;

    uint8_t previous_sw_state = GPIO_PIN_4;
    uint8_t debounce_sw_state = GPIO_PIN_4;
    uint8_t current_sw_state = GPIO_PIN_4;

    // Infinite loop for polling UART
    while (true) {
        // Non blocking UART polling
        if (uart_avail(HOST_UART)) {
            uint8_t uart_char = (uint8_t)uart_readb(HOST_UART);

            if ((uart_char != '\r') && (uart_char != '\n') &&
                (uart_char != '\0') && (uart_buffer_index < 9)) {
                uart_buffer[uart_buffer_index] = uart_char;
                uart_buffer_index++;
            } else {
                uart_buffer[uart_buffer_index] = 0x00;
                uart_buffer_index = 0;

                if (!(strcmp((char *)uart_buffer, "enable"))) {
                    enableFeature(&fob_state_ram);
                } else if (!(strcmp((char *)uart_buffer, "pair"))) {
                    pairFob(&fob_state_ram);
                }
            }
        }
        current_sw_state = GPIOPinRead(GPIO_PORTF_BASE, GPIO_PIN_4);
        if ((current_sw_state != previous_sw_state) &&
            (current_sw_state == 0)) {
            // Debounce switch
            for (int i = 0; i < 10000; i++)
                ;
            debounce_sw_state = GPIOPinRead(GPIO_PORTF_BASE, GPIO_PIN_4);
            if (debounce_sw_state == current_sw_state) {
                unlockCar(&fob_state_ram);
                if (receiveAck()) {
                    startCar(&fob_state_ram);
                }
            }
        }
        previous_sw_state = current_sw_state;
    }
}

/**
 * @brief Function that carries out pairing of the fob
 *
 * @param fob_state_ram pointer to the current fob state in ram
 */
void pairFob(FLASH_DATA *fob_state_ram) {
    MESSAGE_PACKET message;
    uint8_t size = sizeof(SIG_PK_PACKET);
    uint8_t uart_buffer[size];

    SIG_PK_PACKET *sig_pk_packet = (SIG_PK_PACKET *)uart_buffer;

    // Start pairing transaction - logic for fob that is already paired
    if (fob_state_ram->paired == FLASH_PAIRED) {
        int16_t bytes_read;
        uart_write(HOST_UART, (uint8_t *)"P", 1);

        uint8_t pin_buffer[8];
        bytes_read = uart_read(HOST_UART, pin_buffer, 6);

        // If the pin is incorrect, do nothing
        if (bytes_read != 6 ||
            memcmp(pin_buffer, fob_state_ram->pair_info.pin, 6)) {
            sendAckFailure();
            return;
        }

        sendAckSuccess();

        // Generate a new ephimeral private and public key pair
        uint8_t paired_sk[32];
        uint8_t paired_pk[32];
        uint8_t shared_secret[32];

        get_random_bytes(paired_sk, 32);
        crypto_x25519_public_key(paired_pk, paired_sk);

        memcpy((void *)sig_pk_packet->pubkey,
               (void *)fob_state_ram->pair_info.pubkey, PUBKEY_LEN);
        memcpy((void *)sig_pk_packet->signature,
               (void *)fob_state_ram->pair_info.pubkey_cert, SIGNATURE_LEN);
        memcpy((void *)sig_pk_packet->ake_pk, (void *)paired_pk, PUBKEY_LEN);

        message.message_len = sizeof(SIG_PK_PACKET);
        message.magic = SIG_MAGIC;
        message.buffer = (uint8_t *)sig_pk_packet;
        send_board_message(&message);

        if (!receiveAck()) {
            return;
        }

        // get the unpaired fob public key
        receive_board_message_by_type(&message, AKE_MAGIC, PUBKEY_LEN);
        uint8_t unpaired_pk[PUBKEY_LEN];
        memcpy(unpaired_pk, message.buffer, PUBKEY_LEN);

        // calculate the shared key
        crypto_x25519(shared_secret, paired_sk, unpaired_pk);
        crypto_wipe(paired_sk, 32);

        uint8_t shared_keys[64]; /* Two shared session keys */
        crypto_blake2b_ctx ctx;
        crypto_blake2b_init(&ctx);
        crypto_blake2b_update(&ctx, shared_secret, 32);
        crypto_blake2b_update(&ctx, paired_pk, 32);
        crypto_blake2b_update(&ctx, unpaired_pk, 32);
        crypto_blake2b_final(&ctx, shared_keys);
        uint8_t *key_1 = shared_keys;      /* Shared key 1 */
        uint8_t *key_2 = shared_keys + 32; /* Shared key 2 */
        /* Wipe secrets if they are no longer needed */
        crypto_wipe(shared_secret, 32);

        // Start AKE
        uint8_t ake_buffer[sizeof(PREAUTH_PACKET)];
        PREAUTH_PACKET *preauth_packet = (PREAUTH_PACKET *)ake_buffer;
        get_random_bytes(preauth_packet->nonce, NONCE_LEN);

        uint8_t msg[PUBKEY_LEN * 2];
        memcpy(msg, paired_pk, PUBKEY_LEN);
        memcpy(msg + PUBKEY_LEN, unpaired_pk, PUBKEY_LEN);
        crypto_sign(preauth_packet->ciphertext + 2,
                    fob_state_ram->pair_info.privkey,
                    fob_state_ram->pair_info.pubkey, msg, sizeof(msg));
        preauth_packet->ciphertext[0] = (uint8_t)'P';
        preauth_packet->ciphertext[1] = (uint8_t)'U';

        crypto_lock(preauth_packet->mac, preauth_packet->ciphertext, key_1,
                    preauth_packet->nonce, preauth_packet->ciphertext,
                    2 + SIGNATURE_LEN);

        message.message_len = sizeof(PREAUTH_PACKET);
        message.magic = AKE_MAGIC;
        message.buffer = (uint8_t *)preauth_packet;

        send_board_message(&message);

        if (!receiveAck()) {
            return;
        }

        // get the unpaired fob data and verify it
        receive_board_message_by_type(&message, AKE_MAGIC,
                                      sizeof(PREAUTH_PACKET));
        preauth_packet = (PREAUTH_PACKET *)message.buffer;

        // decrypt the data
        if (crypto_unlock(preauth_packet->ciphertext, key_1,
                          preauth_packet->nonce, preauth_packet->mac,
                          preauth_packet->ciphertext, 2 + SIGNATURE_LEN)) {
            crypto_wipe(preauth_packet, sizeof(PREAUTH_PACKET));
            sendAckFailure();
            return;
        };

        // verify the signature
        memcpy(msg, unpaired_pk, PUBKEY_LEN);
        memcpy(msg + PUBKEY_LEN, paired_pk, PUBKEY_LEN);
        if (preauth_packet->ciphertext[0] != (uint8_t)'U' ||
            preauth_packet->ciphertext[1] != (uint8_t)'P' ||
            crypto_check(preauth_packet->ciphertext + 2,
                         (uint8_t *)UNPAIRED_FOB_PK, msg, PUBKEY_LEN * 2)) {
            crypto_wipe(preauth_packet, sizeof(PREAUTH_PACKET));
            sendAckFailure();
            return;
        }

        crypto_wipe(key_1, KEY_LEN);
        sendAckSuccess();

        uint8_t crypto_meta[sizeof(SYMMETRIC_DATA)];
        uint8_t pair_data[sizeof(PAIR_PACKET)];

        SYMMETRIC_DATA *crypto_packet = (SYMMETRIC_DATA *)crypto_meta;
        get_random_bytes(crypto_packet->nonce, NONCE_LEN);
        crypto_lock(crypto_packet->mac, pair_data, key_2, crypto_packet->nonce,
                    (uint8_t *)&fob_state_ram->pair_info, sizeof(PAIR_PACKET));

        message.message_len = sizeof(SYMMETRIC_DATA);
        message.magic = CRYPTO_MAGIC;
        message.buffer = crypto_meta;
        send_board_message(&message);

        if (!receiveAck()) {
            crypto_wipe(key_2, KEY_LEN);
            return;
        }

        // Pair the new key by sending a PAIR_PACKET structure
        // with required information to unlock door in encrypted form
        message.message_len = sizeof(PAIR_PACKET);
        message.magic = PAIR_MAGIC;
        message.buffer = pair_data;
        send_board_message(&message);

        if (!receiveAck()) {
            crypto_wipe(key_2, KEY_LEN);
            return;
        }

        crypto_wipe(key_2, KEY_LEN);

        // Signify the paired fob is done with its job
        uart_write(HOST_UART, (uint8_t *)"P", 1);
    }

    // Start pairing transaction - fob is not paired
    else {
        // get confirmation that pin is correct
        if (!receiveAck()) {
            return;
        }

        message.buffer = (uint8_t *)sig_pk_packet;
        receive_board_message_by_type(&message, SIG_MAGIC,
                                      sizeof(SIG_PK_PACKET));

        // Verify the signature
        if (crypto_check(sig_pk_packet->signature, (uint8_t *)CA_PK,
                         sig_pk_packet->pubkey, PUBKEY_LEN)) {
            // unsafe, wipe all the data
            crypto_wipe(sig_pk_packet, size);
            sendAckFailure();
            return;
        }

        sendAckSuccess();

        // Generate a new ephimeral private and public key pair
        uint8_t unpaired_sk[32];
        uint8_t unpaired_pk[32];
        uint8_t shared_secret[32];
        uint8_t paired_pk[32];
        uint8_t signed_paired_pk[32];

        memcpy(paired_pk, sig_pk_packet->ake_pk, PUBKEY_LEN);
        memcpy(signed_paired_pk, sig_pk_packet->pubkey, PUBKEY_LEN);

        get_random_bytes(unpaired_sk, 32);
        crypto_x25519_public_key(unpaired_pk, unpaired_sk);

        message.message_len = PUBKEY_LEN;
        message.magic = AKE_MAGIC;
        message.buffer = unpaired_pk;
        send_board_message(&message);

        // Calculate shared secrets
        crypto_x25519(shared_secret, unpaired_sk, paired_pk);
        crypto_wipe(unpaired_sk, 32);

        uint8_t shared_keys[64]; /* Two shared session keys */
        crypto_blake2b_ctx ctx;
        crypto_blake2b_init(&ctx);
        crypto_blake2b_update(&ctx, shared_secret, 32);
        crypto_blake2b_update(&ctx, paired_pk, 32);
        crypto_blake2b_update(&ctx, unpaired_pk, 32);
        crypto_blake2b_final(&ctx, shared_keys);
        uint8_t *key_1 = shared_keys;      /* Shared key 1 */
        uint8_t *key_2 = shared_keys + 32; /* Shared key 2 */
        /* Wipe secrets if they are no longer needed */
        crypto_wipe(shared_secret, 32);

        // Start AKE
        uint8_t ake_buffer[sizeof(PREAUTH_PACKET)];
        PREAUTH_PACKET *preauth_packet = (PREAUTH_PACKET *)ake_buffer;

        // Receive and validate the preauth packet
        message.buffer = (uint8_t *)preauth_packet;
        receive_board_message_by_type(&message, AKE_MAGIC,
                                      sizeof(PREAUTH_PACKET));

        // decrypt the data
        if (crypto_unlock(preauth_packet->ciphertext, key_1,
                          preauth_packet->nonce, preauth_packet->mac,
                          preauth_packet->ciphertext, 2 + SIGNATURE_LEN)) {
            crypto_wipe(preauth_packet, sizeof(PREAUTH_PACKET));
            sendAckFailure();
            return;
        };

        // verify the signature
        uint8_t msg[PUBKEY_LEN * 2];
        memcpy(msg, paired_pk, PUBKEY_LEN);
        memcpy(msg + PUBKEY_LEN, unpaired_pk, PUBKEY_LEN);
        if (preauth_packet->ciphertext[0] != (uint8_t)'P' ||
            preauth_packet->ciphertext[1] != (uint8_t)'U' ||
            crypto_check(preauth_packet->ciphertext + 2, signed_paired_pk, msg,
                         PUBKEY_LEN * 2)) {
            crypto_wipe(preauth_packet, sizeof(PREAUTH_PACKET));
            sendAckFailure();
            return;
        }

        sendAckSuccess();

        get_random_bytes(preauth_packet->nonce, NONCE_LEN);
        memcpy(msg, unpaired_pk, PUBKEY_LEN);
        memcpy(msg + PUBKEY_LEN, paired_pk, PUBKEY_LEN);
        crypto_sign(preauth_packet->ciphertext + 2, (uint8_t *)UNPAIRED_FOB_SK,
                    (uint8_t *)UNPAIRED_FOB_PK, msg, PUBKEY_LEN * 2);
        preauth_packet->ciphertext[0] = (uint8_t)'U';
        preauth_packet->ciphertext[1] = (uint8_t)'P';

        crypto_lock(preauth_packet->mac, preauth_packet->ciphertext, key_1,
                    preauth_packet->nonce, preauth_packet->ciphertext,
                    2 + SIGNATURE_LEN);

        message.message_len = sizeof(PREAUTH_PACKET);
        message.magic = AKE_MAGIC;
        message.buffer = (uint8_t *)preauth_packet;

        send_board_message(&message);

        if (!receiveAck()) {
            crypto_wipe(key_1, KEY_LEN);
            return;
        }

        crypto_wipe(key_1, KEY_LEN);

        uint8_t crypto_meta[sizeof(SYMMETRIC_DATA)];
        SYMMETRIC_DATA *crypto_packet = (SYMMETRIC_DATA *)crypto_meta;

        message.buffer = (uint8_t *)crypto_packet;
        receive_board_message_by_type(&message, CRYPTO_MAGIC,
                                      sizeof(SYMMETRIC_DATA));

        sendAckSuccess();

        // Receive the paired fob data: FINALLY
        message.buffer = (uint8_t *)&fob_state_ram->pair_info;
        receive_board_message_by_type(&message, PAIR_MAGIC,
                                      sizeof(PAIR_PACKET));

        if (crypto_unlock((uint8_t *)&fob_state_ram->pair_info, key_2,
                          crypto_packet->nonce, crypto_packet->mac,
                          (uint8_t *)&fob_state_ram->pair_info,
                          sizeof(PAIR_PACKET))) {
            crypto_wipe(key_2, KEY_LEN);
            sendAckFailure();
            return;
        }

        fob_state_ram->paired = FLASH_PAIRED;
        fob_state_ram->feature_info.car_id = fob_state_ram->pair_info.car_id;

        sendAckSuccess();

        uart_write(HOST_UART, (uint8_t *)"Paired", 6);

        saveFobState(fob_state_ram);
    }
}

/**
 * @brief Function that handles enabling a new feature on the fob
 *
 * @param fob_state_ram pointer to the current fob state in ram
 */
void enableFeature(FLASH_DATA *fob_state_ram) {
    // Only allow enabling of features if fob is paired
    if (fob_state_ram->paired == FLASH_PAIRED) {
        uint8_t size = sizeof(ENABLE_PACKET);
        uint8_t read_bytes = 0;
        uint8_t uart_buffer[size];

        while (read_bytes < size) {
            read_bytes += uart_read(HOST_UART, uart_buffer + read_bytes, size);
        }

        ENABLE_PACKET *enable_message = (ENABLE_PACKET *)uart_buffer;

        // decrypt the data in place
        if (crypto_unlock(&enable_message->car_id,
                          fob_state_ram->pair_info.link_key,
                          enable_message->nonce, enable_message->mac,
                          &enable_message->car_id, 2)) {
            // unsafe, wipe all data
            crypto_wipe(enable_message, size);
            return;
        }

        // check certificate
        if (crypto_check(enable_message->signature, (uint8_t *)CA_PK,
                         &enable_message->car_id, 2)) {
            // unsafe, wipe all the data
            crypto_wipe(enable_message, size);
            return;
        }

        if (fob_state_ram->pair_info.car_id != enable_message->car_id) {
            // Not intended for this car
            crypto_wipe(enable_message, size);
            return;
        }

        // Feature list full
        if (fob_state_ram->feature_info.num_active == NUM_FEATURES) {
            crypto_wipe(enable_message, size);
            return;
        }

        // Search for feature in list
        for (int i = 0; i < fob_state_ram->feature_info.num_active; i++) {
            if (fob_state_ram->feature_info.features[i] ==
                enable_message->feature) {
                crypto_wipe(enable_message, size);
                return;
            }
        }

        fob_state_ram->feature_info
            .features[fob_state_ram->feature_info.num_active] =
            enable_message->feature;
        memcpy(fob_state_ram->feature_info
                   .signatures[fob_state_ram->feature_info.num_active],
               enable_message->signature, SIGNATURE_LEN);
        fob_state_ram->feature_info.num_active++;

        saveFobState(fob_state_ram);
        uart_write(HOST_UART, (uint8_t *)"Enabled", 7);

        crypto_wipe(enable_message, size);
    }
}

/**
 * @brief Function that handles the fob unlocking a car
 *
 * @param fob_state_ram pointer to the current fob state in ram
 */
void unlockCar(FLASH_DATA *fob_state_ram) {
    if (fob_state_ram->paired == FLASH_UNPAIRED) {
        return;
    }

    MESSAGE_PACKET message;
    message.message_len = 6;
    message.magic = UNLOCK_MAGIC;
    message.buffer = (uint8_t *)"Unlock";
    send_board_message(&message);

    if (!receiveAck()) {
        return;
    }

    uint8_t buffer[sizeof(UNLOCK_PACKET)];
    message.buffer = buffer;
    receive_board_message_by_type(&message, CHALLENGE_MAGIC,
                                  sizeof(UNLOCK_PACKET));

    UNLOCK_PACKET *unlock_packet = (UNLOCK_PACKET *)message.buffer;
    if (crypto_unlock(unlock_packet->challenge,
                      fob_state_ram->pair_info.link_key, unlock_packet->nonce,
                      unlock_packet->mac, unlock_packet->challenge, KEY_LEN)) {
        crypto_wipe(unlock_packet, sizeof(UNLOCK_PACKET));
        sendAckFailure();
        return;
    }

    sendAckSuccess();

    uint8_t response[KEY_LEN + 6];
    memcpy(response, "Unlock", 6);
    memcpy(response + 6, unlock_packet->challenge, KEY_LEN);
    get_random_bytes(unlock_packet->nonce, NONCE_LEN);

    crypto_lock(unlock_packet->mac, unlock_packet->challenge,
                fob_state_ram->pair_info.link_key, unlock_packet->nonce,
                response, KEY_LEN + 6);

    // Send response
    message.magic = CHALLENGE_MAGIC;
    message.message_len = sizeof(UNLOCK_PACKET);
    send_board_message(&message);
}

/**
 * @brief Function that handles the fob starting a car
 *
 * @param fob_state_ram pointer to the current fob state in ram
 */
void startCar(FLASH_DATA *fob_state_ram) {
    if (fob_state_ram->paired == FLASH_PAIRED) {
        MESSAGE_PACKET message;
        message.magic = START_MAGIC;
        message.message_len = sizeof(FEATURE_DATA);
        message.buffer = (uint8_t *)&fob_state_ram->feature_info;
        send_board_message(&message);
    }
}

/**
 * @brief Function that erases and rewrites the non-volatile data to flash
 *
 * @param info Pointer to the flash data ram
 */
void saveFobState(FLASH_DATA *flash_data) {
    FlashErase(FOB_STATE_PTR);
    FlashProgram((uint32_t *)flash_data, FOB_STATE_PTR, FLASH_DATA_SIZE);
}

/**
 * @brief Function that receives an ack and returns whether ack was
 * success/failure
 *
 * @return uint8_t Ack success/failure
 */
uint8_t receiveAck() {
    MESSAGE_PACKET message;
    uint8_t buffer[1];
    message.buffer = buffer;
    receive_board_message_by_type(&message, ACK_MAGIC, 1);

    return message.buffer[0];
}

/**
 * @brief Function to send successful ACK message
 */
void sendAckSuccess(void) {
    // Create packet for successful ack and send
    MESSAGE_PACKET message;

    uint8_t buffer[1];
    message.buffer = buffer;
    message.magic = ACK_MAGIC;
    buffer[0] = ACK_SUCCESS;
    message.message_len = 1;

    send_board_message(&message);
}

/**
 * @brief Function to send unsuccessful ACK message
 */
void sendAckFailure(void) {
    // Create packet for unsuccessful ack and send
    MESSAGE_PACKET message;

    uint8_t buffer[1];
    message.buffer = buffer;
    message.magic = ACK_MAGIC;
    buffer[0] = ACK_FAIL;
    message.message_len = 1;

    send_board_message(&message);
}
