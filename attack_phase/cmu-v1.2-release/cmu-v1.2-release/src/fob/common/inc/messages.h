// Format of all messages between boards.
// ALL MESSAGES MUST NOT HAVE ANY IMPLICIT PADDING BYTES.

#ifndef __MESSAGES_
#define __MESSAGES_

#include <stdint.h>
#include "crypto_wrappers.h"

// Features
#define FLASH_FEATURES (0x23800) // features stored from here in PF Flash

// bitmasks for enabled features
#define FEATURE_1_MASK (1)
#define FEATURE_2_MASK (2)
#define FEATURE_3_MASK (4)

// Message types
#define MSG_PAIR_REQUEST     (0x10) // HT -> PF, send pin to init pair
#define MSG_PAIR_SEND        (0x11) // PF -> UPF, pair fob
#define MSG_ENABLE_FEATURE   (0x21) // HT -> PF, enable feature
#define MSG_UNLOCK_START     (0x42) // PF -> C, initiate unlock
#define MSG_UNLOCK_CHALLENGE (0x43) // C -> PF, challenge
#define MSG_UNLOCK_RESPONSE  (0x44) // PF -> C, response

// Sizes
#define PRIVATE_KEY_LEN  (0x20)
#define PUBLIC_KEY_LEN   (0x20)
#define FEATURE_MSG_LEN  (0x40)
#define UNLOCK_MSG_LEN   (0x40)
#define MAX_NUM_FEATURES (3)
#define PIN_SIZE         (6)     // 6 hexadecimal digits
#define SIGNATURE_LEN    (0x40)
#define HASH_LEN         (0x40)  // blake2b from monocypher

// for the response message to the challenge while unlocking car
typedef struct feature{
    uint32_t car_id;
    uint32_t feature_number;
    uint8_t signature[SIGNATURE_LEN];
} feature_t;

// struct used for storing feature info in PF Flash
typedef struct {
    uint8_t active_features; // bitvector for indicating which features are active
	uint8_t padding[3];
    feature_t features_array[MAX_NUM_FEATURES];
    uint32_t fail_count;
} stored_features_t;

// to enable feature
typedef struct enable_feature_message{
	feature_t feature;
} enable_feature_message_t;

// to trigger pair fob
typedef struct request_pairing_message{
	uint8_t message_type;
	uint8_t pin[PIN_SIZE];
} request_pairing_message_t;

// when pairing is successful
typedef struct fob_info {
	uint32_t car_id; // This field must be present to make the struct 4-byte aligned.
	uint8_t car_encryption_public_key[PUBLIC_KEY_LEN];
	uint8_t car_signature_public_key[PUBLIC_KEY_LEN];
	uint8_t deployment_signature_public_key[PUBLIC_KEY_LEN];
	uint8_t unpaired_fob_encryption_public_key[PUBLIC_KEY_LEN];
	uint8_t paired_fob_encryption_private_key[PRIVATE_KEY_LEN];
	uint8_t paired_fob_signature_private_key[PRIVATE_KEY_LEN];
	uint8_t pin_hash[HASH_LEN];
	uint8_t pin_hash_key[HASH_LEN];
} fob_info_t;

typedef struct clone_fob_message {
	uint8_t message_type;
	uint8_t encrypted_fob_info[sizeof(fob_info_t)+CC_ENC_ASYM_METADATA_LEN];
} clone_fob_message_t;

// for the first message to unlock car
typedef struct unlock_message{
	uint8_t message_type;
} unlock_message_t;

// for the reply from car during unlock car
typedef struct challenge{
	uint64_t nonce;
	uint8_t signed_nonce[SIGNATURE_LEN];
} challenge_t;

typedef struct challenge_message {
	uint8_t message_type;
	uint8_t encrypted_challenge[sizeof(challenge_t)+CC_ENC_ASYM_METADATA_LEN];
} challenge_message_t;

// All of this data gets signed in order to be sent to the car.
typedef struct response_body {
	uint64_t nonce;
	uint8_t message_type; // here for verification
    uint8_t active_features; // bitvector for active features
	uint8_t padding[2];
	feature_t signed_features[MAX_NUM_FEATURES];
} response_body_t;

typedef struct response{
	response_body_t body;
	uint8_t signature[SIGNATURE_LEN]; // the body, signed by PF
} response_t;

// for the response message to the challenge while unlocking car
typedef struct response_message{
	uint8_t message_type;
	uint8_t encrypted_response[sizeof(response_t)+CC_ENC_ASYM_METADATA_LEN];
} response_message_t;

#endif
