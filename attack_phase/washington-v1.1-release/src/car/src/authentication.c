#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "inc/bearssl_rand.h"
#include "inc/bearssl_hash.h"
#include "inc/bearssl_hmac.h"
#include "inc/bearssl_block.h"
#include "inc/hw_memmap.h"
#include "driverlib/gpio.h"
#include "authentication.h"
#include "uart.h"


/**
 * @brief Zeroes a message and sets the nonces
 * 
 * @param message the message to be initialized
 */
void init_message(Message* message) {
    memset(&current_msg, 0, sizeof(current_msg));
    message->c_nonce = c_nonce;
    message->s_nonce = s_nonce;
    message->target = TO_P_FOB;
}


/**
 * @brief Verifies that a given message is authenticated and valid.
 * 
 * @return true if all of the following conditions are met:
 *  - message target matches device type
 *  - client and server nonces are valid
 *  - the message type is expected
 *  - the hmac of the message is valid
 * @return false otherwise
 * 
 * @param message the message to be verified
 */
bool verify_message(Message* message) {

    // Ensure message is going to the correct device type
    if(message->target != dev_secrets.device_type) {
        return false;
    }

    // Ensure the client nonce is valid if it needs to be
    if(message->msg_magic != HELLO && message->c_nonce != c_nonce) {
        return false;
    }
    
    // Ensure the server nonce is valid if it needs to be
    if (message->msg_magic != HELLO && message->msg_magic != CHALL && message->s_nonce != s_nonce)
    {
       return false;
    }

    // Redundant(?) check to ensure there is a payload
    if(message->payload_size < 1) {
        return false;
    }

    // Ensure that the recieved packet type is the expected type of packet to be recieved
    if(next_packet_type != message->msg_magic || next_packet_type == 0) {
        return false;
    }

    // Ensure that the hmac of the packet is valid
    uint8_t hash[32];
    br_hmac_context ctx_hmac;
    br_hmac_init(&ctx_hmac, &ctx_hmac_key, sizeof(hash));
    br_hmac_update(&ctx_hmac, &message, sizeof(Message) - 36); //everything except hash (and frags)

    br_hmac_out(&ctx_hmac, hash);

    if(!memcmp(hash, message->payload_hash, sizeof(hash))) {
        return false;
    }

    return true;
}

/**
 * @brief Finalizes the addition of a payload to a message by signing it and adding the hash & size fields
 * 
 * @param message the message to be signed
 * @param size the size of the message's payload
 */
void message_sign_payload(Message* message, size_t size) {

    //make sure the size isn't too large
    if(size > PAYLOAD_BUF_SIZE) {
        return;
    }

    //set the size
    message->payload_size = size;

    br_hmac_context ctx_hmac;
    br_hmac_init(&ctx_hmac, &ctx_hmac_key, sizeof(message->payload_hash));
    br_hmac_update(&ctx_hmac, message, sizeof(Message) - 36); //everything except hash (and frags)

    br_hmac_out(&ctx_hmac, message->payload_hash);
}

/**
 * Attempts to read a message packet from UART and parses it.
 * 
 * This is where the core Conversation logic occurs - the function
 * verifies that the incoming message is authenticated and valid and
 * parses the data accordingly.
 * 
 * It then attempts to craft a response to the incoming packet
 * 
 * If the incoming packet is invalid or times out, the internal state of the current conversation
 * is reset.
 * 
 * @return true if the message was valid and parseable
 */
bool parse_inc_message(void) {
    if(!uart_read_message(DEVICE_UART, &current_msg)) {
        //reset_state();
        return false;
    }

    //remove second verification if slow
    if(!verify_message(&current_msg)) {
        memset(&current_msg, 0, sizeof(Message));
        reset_state();
        return false;
    }

    switch (current_msg.msg_magic)
    {

    case HELLO:
        if(handle_hello(&current_msg)) {
            gen_chall();
        }
        else {
            reset_state();
            return false;
        }
        break;
    case SOLVE:
        if(handle_solution(&current_msg)) {

            // Change LED color: green
            GPIOPinWrite(GPIO_PORTF_BASE, GPIO_PIN_1, 0); // r
            GPIOPinWrite(GPIO_PORTF_BASE, GPIO_PIN_2, 0); // b
            GPIOPinWrite(GPIO_PORTF_BASE, GPIO_PIN_3, GPIO_PIN_3); // g

            gen_end();
        }
        else {
            reset_state();
            return false;
        }
        break;

    default:
        reset_state();
        return false;
    }

    return true;
}

void send_next_message(void) {

    if(is_msg_ready) {
        is_msg_ready = false;
        uart_send_message(DEVICE_UART, &current_msg);
    }
}


/************************************************************************************
 * The following section of functions is reserved only for use with a car fimrware. *
 * A fob (paired or unpaired) does not require these functions.                     *
 ************************************************************************************/


/**
 * @brief Parses a recieved hello message as part of the Conversation protocol
 * 
 * This method stores the challenge data from a given challenge message
 * 
 * See util.h for more information about the Conversation protocol.
 * 
 * @param message the message to be handled
 * 
 * @return true if the packet is valid.
 * @return false if the packet is invalid.
 */
bool handle_hello(Message* message) {

    if(message->payload_size != sizeof(PacketHello)) {
        return false;
    }

    c_nonce = message->c_nonce;
    rand_get_bytes(&s_nonce, sizeof(s_nonce));

    PacketHello* p = (PacketHello*) &message->payload_buf;

    memcpy(challenge, p->chall, sizeof(challenge));

    return true;
}


// Verifies a feature to ensure that it is valid
bool verify_feature(Feature* feature, uint8_t id) {

    if(id < 1 || id > 3) {
        return false;
    }

    br_aes_ct_cbcdec_keys ctx_aes;
    br_aes_ct_cbcdec_init(&ctx_aes, feature_key, 16);
    br_aes_ct_cbcdec_run(&ctx_aes, &feature->data[16], feature->data, 16); // first 16 bytes are ct, next 16 bytes are iv (flipped)

   

    uint8_t feat_hash[32];
    br_sha256_context ctx_sha_f;
    br_sha256_init(&ctx_sha_f);
    br_sha256_update(&ctx_sha_f, feature->data, 16);
    
    br_sha256_out(&ctx_sha_f, feat_hash);
    
    uint8_t stored_hash[32];
    eeprom_read(stored_hash, 32, EEPROM_FEAT_HASH_ADDR + 32 * (id - 1));

    // redundant check to make sure car id and feature num matches
    if(feature->data[0] != CAR_ID || feature->data[1] != id) {
        return false;
    }

    // prob should be timingsafe but oh well
    return memcmp(feat_hash, stored_hash, 32) == 0;
}

/**
 * @brief Parses a recieved solution message as part of the Conversation protocol
 * 
 * This method verifies that the given solution to the previous challenges matches
 * the self-computed soluton.
 * 
 * See util.h for more information about the Conversation protocol.
 * 
 * @param message the message to be handled
 * 
 * @return true if the packet's solution is valid.
 * @return false if the packet is invalid or the solution is wrong.
 */
bool handle_solution(Message* message) {

    if(message->payload_size != sizeof(PacketSolution)) {
        return false;
    }
    PacketSolution* p = (PacketSolution*) &message->payload_buf;
    verified_features = 0;

    //verify the challenge/response is valid
    uint8_t auth_hash[32];

    br_sha256_context ctx_sha2;
    br_sha256_init(&ctx_sha2);
    br_sha256_update(&ctx_sha2, challenge, sizeof(challenge));
    br_sha256_update(&ctx_sha2, challenge_resp, sizeof(challenge_resp));
    br_sha256_update(&ctx_sha2, dev_secrets.car_secret, sizeof(dev_secrets.car_secret));
    br_sha256_update(&ctx_sha2, &c_nonce, sizeof(c_nonce));
    br_sha256_update(&ctx_sha2, &s_nonce, sizeof(s_nonce));
    br_sha256_out(&ctx_sha2, auth_hash);

    if(!memcmp(auth_hash, p->response, sizeof(auth_hash))) {
        return false;
    }
    
    

    //verify the features are all valid
    CommandUnlock* cmd = &p->command;
    
    if(cmd->feature_flags == 0 || cmd->feature_flags == 0xff) {
        verified_features = 0;
        return true;
    }

    if(cmd->feature_flags & 0x01) {
        if(!verify_feature(&cmd->feature_a, 1)) {
            return false;
        }
    }
    
    if(cmd->feature_flags & 0x02) {
        if(!verify_feature(&cmd->feature_b, 2)) {
            return false;
        }
    }

    if(cmd->feature_flags & 0x04) {
        if(!verify_feature(&cmd->feature_c, 3)) {
            return false;
        }
    }

    verified_features = cmd->feature_flags;

    return true;
}


/**
 * @brief Creates a challenge message as part of the Conversation protocol
 * 
 * This is the second packet to be sent in a sequence (Car -> Paired Fob)
 * 
 * See util.h for more information about the Conversation protocol.
 */
void gen_chall(void) {

    init_message(&current_msg);

    current_msg.msg_magic = CHALL;
    current_msg.target = TO_P_FOB;

    PacketChallenge* p = (PacketChallenge*) &current_msg.payload_buf;
    rand_get_bytes(challenge, sizeof(challenge));
    memcpy(p->chall, challenge, sizeof(challenge));

    message_sign_payload(&current_msg, sizeof(PacketChallenge));

    next_packet_type = SOLVE;
    is_msg_ready = true;
}


/**
 * @brief Creates an end message as part of the Conversation protocol
 * 
 * This is the fourth and final packet to be sent in a sequence (Car -> Paired Fob).
 * Currently, the only functionality of this packet is to send an unlock message (TODO)
 * 
 * See util.h for more information about the Conversation protocol.
 */
void gen_end(void) {

    init_message(&current_msg);

    current_msg.msg_magic = END;
    current_msg.target = TO_P_FOB;

    uint8_t unlock_msg[64];

    eeprom_read(unlock_msg, sizeof(unlock_msg), EEPROM_UNLOCK_ADDR);
    uart_send_raw(HOST_UART, unlock_msg, sizeof(unlock_msg));

    if(verified_features & 0x01) {
        eeprom_read(unlock_msg, sizeof(unlock_msg), EEPROM_FEAT_A_ADDR);
        uart_send_raw(HOST_UART, unlock_msg, sizeof(unlock_msg));
    }
    
    if(verified_features & 0x02) {
        eeprom_read(unlock_msg, sizeof(unlock_msg), EEPROM_FEAT_B_ADDR);
        uart_send_raw(HOST_UART, unlock_msg, sizeof(unlock_msg));
    }

    if(verified_features & 0x04) {
        eeprom_read(unlock_msg, sizeof(unlock_msg), EEPROM_FEAT_C_ADDR);
        uart_send_raw(HOST_UART, unlock_msg, sizeof(unlock_msg));
    }

    next_packet_type = HELLO;
    verified_features = 0;
    is_msg_ready = true;
}

/**
 * @brief Resets the internal state of the Conversation sequence.
 * 
 * Creates new nonces.
 *
 * The next expected packet type is set to HELLO (although this will only be used with the Car)
 * 
 * The stored challenge and challenge responses are reset.
 */
void reset_state(void) {

    rand_get_bytes(&c_nonce, sizeof(c_nonce));
    rand_get_bytes(&s_nonce, sizeof(s_nonce));

    next_packet_type = HELLO;
    is_msg_ready = false;

    rand_get_bytes(challenge, sizeof(challenge));
    rand_get_bytes(challenge_resp, sizeof(challenge_resp));
}


/**
 * Function that initializes the pseudorandom generator with entropy from the following sources:
 *  - factory seed
 *  - persistent mutating code stored in eeprom
 *  - random bits from uninitialized section of ram
 *  - temperature (TODO)
 * 
 * Upon initialization, it overrides the stored seed in eeprom with a different value.
 * Also initializes HMAC context
 */
void rand_init(void) {

    //initialize eeprom
    eeprom_init();

    // Update rand with factory seed
    uint8_t e_factory[32] = FACTORY_ENTROPY;
    br_hmac_drbg_init(&ctx_rand, &br_sha256_vtable, e_factory, sizeof(e_factory));
    
    // Update rand with EEPROM seed
    uint8_t seed[SEED_SIZE];
    eeprom_read(seed, SEED_SIZE, EEPROM_RAND_ADDR);
    br_hmac_drbg_update(&ctx_rand, seed, SEED_SIZE);

    // Update rand with uninitialized ram
    br_sha256_context sha_ctx;
    br_sha256_init(&sha_ctx);
    br_sha256_update(&sha_ctx, (uint8_t*) &rand_uninit_addr, 2048);
    uint8_t hash_out[32];
    br_sha256_out(&sha_ctx, hash_out);
    br_hmac_drbg_update(&ctx_rand, hash_out, 32);

    //override old source of persistent memory with new value
    br_hmac_drbg_generate(&ctx_rand, seed, SEED_SIZE);
    eeprom_write(seed, SEED_SIZE, EEPROM_RAND_ADDR);

    is_random_set = 1;
}

void secrets_init(void) {
    eeprom_read(&dev_secrets, sizeof(Secrets), EEPROM_SECRETS_ADDR);
    //also init hmac while we're at it
    br_hmac_key_init(&ctx_hmac_key, &br_sha256_vtable, dev_secrets.car_secret, sizeof(dev_secrets.car_secret));
}

uint8_t get_dev_type(void) {
    return dev_secrets.device_type;
}

void first_boot(void) {
    memcpy(dev_secrets.car_secret, car_secret, sizeof(car_secret));
    dev_secrets.pair_pin = 0;
    dev_secrets.car_id = CAR_ID;

    #if defined(CAR_TARGET)
    dev_secrets.device_type = TO_CAR;
    #else
    if(PAIRED) {
         dev_secrets.device_type = TO_P_FOB;
    }
    else {
        dev_secrets.device_type = TO_U_FOB;
    }
    #endif

    eeprom_write(&dev_secrets, sizeof(Secrets), EEPROM_SECRETS_ADDR);
}

/**
 * @brief gets random bytes from internal prng
 * 
 * @param out buffer to store random bytes
 * @param len number of bytes to write
 */
void rand_get_bytes(void* out, size_t len) {
    br_hmac_drbg_generate(&ctx_rand, out, len);
}