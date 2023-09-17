#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "inc/bearssl_rand.h"
#include "inc/bearssl_hash.h"
#include "inc/bearssl_hmac.h"
#include "inc/hw_memmap.h"
#include "driverlib/sysctl.h"
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

    message->target = TO_CAR;
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

    //make sure packet is valid
    if(!uart_read_message(DEVICE_UART, &current_msg)) {
        //reset_state();
        return false;
    }

    if(current_msg.msg_magic == 'P' && current_msg.target == dev_secrets.device_type) {
        if(dev_secrets.device_type == TO_U_FOB) {
            handle_pair_resp(&current_msg);
        }
        else if(dev_secrets.device_type == TO_P_FOB) {
            handle_pair_request(&current_msg);
        }

        reset_state();
        return true;
    }

    if(!verify_message(&current_msg)) {
        memset(&current_msg, 0, sizeof(Message));
        #ifdef DEBUG
        debug_print("msg verification fail\n");
        #endif
        reset_state();
        return false;
    }

    switch (current_msg.msg_magic)
    {
    case CHALL:
        if(handle_chall(&current_msg)) {
            gen_solution();
        }
        else {
            reset_state();
            return false;
        }
        break;
    case END:
        handle_end(&current_msg);
        reset_state();
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
 * The following section of functions is reserved only for use with a fob fimrware. *
 * A car does not require these functions.                                          *
 ************************************************************************************/


/**
 * @brief Starts a conversation with a car to unlock the fob
 * 
 * This function should be called when the unlock button is pressed on a fob.
 * It resets the internal state of the current active conversation and
 * sends a new hello message through the device UART.
 */
void start_unlock_sequence(void) {
    reset_state();
    gen_hello();
    send_next_message();
}

/**
 * @brief Creates a hello message as part of the Conversation protocol
 * 
 * This is the first packet to be sent in a sequence (Paired Fob -> Car)
 * 
 * See util.h for more information about the Conversation protocol.
 */
void gen_hello(void) {
    init_message(&current_msg);

    current_msg.msg_magic = HELLO;
    current_msg.target = TO_CAR;
    PacketHello* p = (PacketHello*) &current_msg.payload_buf;
    rand_get_bytes(challenge, sizeof(challenge));
    
    memcpy(&p->chall, &challenge, sizeof(challenge)); //is this safe?
    message_sign_payload(&current_msg, sizeof(PacketHello));
    next_packet_type = CHALL;
    is_msg_ready = true;
}

/**
 * @brief Creates a solution message as part of the Conversation protocol
 * 
 * This is the third packet to be sent in a sequence (Paired Fob -> Car)
 * 
 * This method depends on data from a hello packet and a challenge packet to
 * properly compute a valid response.
 * 
 * See util.h for more information about the Conversation protocol.
 */
void gen_solution(void) {

    init_message(&current_msg);

    current_msg.msg_magic = SOLVE;
    current_msg.target = TO_CAR;
    PacketSolution* p = (PacketSolution*) &current_msg.payload_buf;


    // use hmac here instead?
    br_sha256_context ctx_sha2;
    br_sha256_init(&ctx_sha2);
    br_sha256_update(&ctx_sha2, challenge, sizeof(challenge));
    br_sha256_update(&ctx_sha2, challenge_resp, sizeof(challenge_resp));
    br_sha256_update(&ctx_sha2, dev_secrets.car_secret, sizeof(dev_secrets.car_secret));
    br_sha256_update(&ctx_sha2, &c_nonce, sizeof(c_nonce));
    br_sha256_update(&ctx_sha2, &s_nonce, sizeof(s_nonce));
    br_sha256_out(&ctx_sha2, p->response);

    p->command_magic = UNLOCK_MGK;    

    eeprom_read(&p->command, sizeof(CommandUnlock) + 3, EEPROM_FEATS_ADDR);
    message_sign_payload(&current_msg, sizeof(PacketSolution));

    next_packet_type = END;
    is_msg_ready = true;
}
/**
 * @brief Parses a recieved challenge message as part of the Conversation protocol
 * 
 * This method stores the challenge data from a given challenge message
 * 
 * See util.h for more information about the Conversation protocol.

 * @param message the message to be handled
 * 
 * @return true if the packet is valid.
 * @return false if the packet is invalid.
 */
bool handle_chall(Message* message) {
    if(message->payload_size != sizeof(PacketChallenge)) {
        return false;
    }
    s_nonce = message->s_nonce;
    PacketChallenge* p = (PacketChallenge*) &(message->payload_buf);

    memcpy(challenge_resp, p->chall, sizeof(challenge_resp));

    return true;
}

/**
 * @brief Parses a recieved end message as part of the Conversation protocol
 * 
 * As of right now, this method just forwards packet data to the host UART interface
 * 
 * See util.h for more information about the Conversation protocol.
 * 
 * @param message the message to be handled
 * 
 * @return true
 */
bool handle_end(Message* message) {

    uart_send_message(HOST_UART, message);
    reset_state();
    return true;
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
    dev_secrets.pair_pin = PAIR_PIN;
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

#ifdef FOB_TARGET

void handle_host_msg(void) {

    uint8_t packet[128];

    uart_read_raw(HOST_UART, packet, sizeof(packet));

    if(packet[0] == UPLOAD_FEATURE) {
        handle_upload_feature(packet);
    }

    else if(packet[0] == PAIR_CMD && dev_secrets.device_type == TO_U_FOB) {
        send_pair_request(packet);
    }

}


void handle_upload_feature(uint8_t* packet) {

    //ensure feature is meant for paired car
    if(packet[1] != dev_secrets.car_id) {
        return;
    }

    CommandUnlock c;
    eeprom_read(&c, sizeof(c), EEPROM_FEATS_ADDR);
    
    //in the case that this is the first time a feature is being added, the eeprom will be filled with 0xFFs
    if(c.feature_flags == 0xff) {
        c.feature_flags = 0;
    }

    if(packet[2] == 1) {
        c.feature_flags |= 0x01;
        memcpy(c.feature_a.data, &packet[3], 32);
    }
    else if(packet[2] == 2) {
        c.feature_flags |= 0x02;
        memcpy(c.feature_b.data, &packet[3], 32);
    }
    else if(packet[2] == 3) {
        c.feature_flags |= 0x04;
        memcpy(c.feature_c.data, &packet[3], 32);
    }

    eeprom_write(&c, sizeof(c), EEPROM_FEATS_ADDR);

    uart_send_raw(HOST_UART, "feature add success!", 20);
}

void send_pair_request(uint8_t* packet) {

    //pointers are for nerds; just memcpy it
    uint32_t pin;
    memcpy(&pin, packet + 1, sizeof(uint32_t));

    Message m;
    m.msg_magic = 'P';
    m.target = TO_P_FOB;
    m.payload_size = sizeof(uint32_t);
    memcpy(&m.payload_buf, &pin, sizeof(uint32_t)); //two memcpys; peak efficiency :D

    uart_send_message(DEVICE_UART, &m);
    reset_state();
}


// A pair request from unpaired fob -> paired fob
void handle_pair_request(Message* packet) {

    if(dev_secrets.device_type != TO_P_FOB) {
        return;
    }

    uint8_t pairing;
    size_t i;


    eeprom_read(&pairing, sizeof(uint8_t), EEPROM_PIN_FLAGS);

    //means a previous pair process was prematurely terminated
    if(pairing == (uint8_t) 0xb6) {
        for(i = 0; i < 4000 * 1000 * 4; i++) {
            __asm__("nop");
        }

        if(i != 4000 * 1000 * 4) {
            return;
        }
    }
    
    //some magic to hopefully prevent corruption (?)
    pairing = 0xb6;
    
    eeprom_write(&pairing, sizeof(uint8_t), EEPROM_PIN_FLAGS);

    // wait 1 second regardless
    for(i = 0; i < 4000 * 1000 * 1; i++) {
             __asm__("nop");
    }
    if(i != 4000 * 1000 * 1) {
            return;
    }

    Secrets out;
    memset(&out, 0, sizeof(Secrets));

    //directly casting is for nerds
    uint32_t pin = packet->payload_buf[0] | (packet->payload_buf[1] << 8) | (packet->payload_buf[2] << 16) | (packet->payload_buf[3] << 24);

    if(pin == dev_secrets.pair_pin) {
        #ifdef DEBUG
        debug_print("PAIR SUCCESS!");
        #endif
        memcpy(&out, &dev_secrets, sizeof(Secrets));

        pairing = 0;
        eeprom_write(&pairing, sizeof(uint8_t), EEPROM_PIN_FLAGS);
    }

    Message m;
    m.msg_magic = 'P';
    m.target = TO_U_FOB;
    m.payload_size = sizeof(Secrets);
    memcpy(m.payload_buf, &out, sizeof(Secrets));

    uart_send_message(DEVICE_UART, &m);
    reset_state();
}

void handle_pair_resp(Message* packet) {
    if(dev_secrets.device_type != TO_U_FOB) {
        return;
    }

    Secrets* s = (Secrets*) &packet->payload_buf;
    if(s->device_type != TO_P_FOB) {
        uart_send_raw(HOST_UART, "pair failure", 12);
        return;
    }

    uart_send_raw(HOST_UART, "pair success", 12);

    eeprom_write(s, sizeof(Secrets), EEPROM_SECRETS_ADDR);
    secrets_init();
}
#endif
