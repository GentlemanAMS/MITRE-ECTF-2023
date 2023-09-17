#ifndef AUTH_H
#define AUTH_H

#define CAR_TARGET

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "inc/bearssl_rand.h"
#include "inc/bearssl_hmac.h"
#include "secrets.h"
#include "uart.h"
#include "util.h"

//random should be stored on EEPROM so it may persist on reset
#define EEPROM_RAND_ADDR 0x200

#ifdef FOB_TARGET

#define EEPROM_FEATS_ADDR 0x400

#endif

#ifdef CAR_TARGET

#define EEPROM_FEAT_C_ADDR 0x700
#define EEPROM_FEAT_B_ADDR 0x740
#define EEPROM_FEAT_A_ADDR 0x780
#define EEPROM_UNLOCK_ADDR 0x7C0

#define EEPROM_FEAT_HASH_ADDR 0x400

#endif

//address of uninitialized memory (use static memory directives in the future?)
static volatile uint8_t rand_uninit_addr __attribute__((section(".noinit"))) ;

#define SEED_SIZE 32

//should be generated in 'secrets.h'
#define FACTORY_ENTROPY SEC_FACTORY_ENTROPY
#define PAIR_PIN SEC_PAIR_PIN
#define CAR_ID SEC_CAR_ID

static uint8_t car_secret[] = SEC_PAIR_SECRET;
static uint8_t feature_key[] = SEC_FEAT_KEY;

#define EEPROM_FIRST_BOOT_FLAG 0x650
#define EEPROM_SECRETS_ADDR 0x110

static Secrets dev_secrets;

//context for random number generator
static br_hmac_drbg_context ctx_rand;
static br_hmac_key_context ctx_hmac_key;
static uint32_t is_random_set = 0; //bool to make sure random is set (unused)

/******************************************************************/
/*         Variables to be used in conversation messaging         */
/******************************************************************/
static uint64_t c_nonce = 0;
static uint64_t s_nonce = 0;

static uint8_t challenge[32];
static uint8_t challenge_resp[32];
static uint8_t next_packet_type = 0; //type of packet expected to be recieved

// All functions creating / modifying a message will use this variable;
// It's probably (marginally) more time-efficient than creating a new message struct every single time
// Regardless, maybe this'll prevent a stack overflow
static Message current_msg;
static bool is_msg_ready = false;
/******************************************************************/


/******************************************************************/
/*              Functions used by both car and fob                */
/******************************************************************/
void init_message(Message* out);

void reset_state(void);

void message_sign_payload(Message* message, size_t size);

bool parse_inc_message(void);

void send_next_message(void);

bool verify_message(Message* message);

void rand_init(void);
void rand_get_bytes(void* out, size_t len);

void secrets_init(void);
uint8_t get_dev_type(void);

void first_boot(void);
/******************************************************************/


/******************************************************************/
/*                       Fob only functions                       */
/******************************************************************/
#ifdef FOB_TARGET

void start_unlock_sequence(void);
void gen_hello(void);
void gen_solution(void);

bool handle_chall(Message* message);
bool handle_end(Message* message);

#endif


/******************************************************************/
/*                       Car only functions                       */
/******************************************************************/

#ifdef CAR_TARGET

void gen_chall(void);
void gen_end(void);

bool handle_hello(Message* message);
bool handle_solution(Message* message);

static uint8_t verified_features = 0;

#endif


#endif