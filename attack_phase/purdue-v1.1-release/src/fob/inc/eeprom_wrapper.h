/**
 * @file eeprom_wrapper.h
 * @author Purdue eCTF Team
 * @brief Header file for eeprom wrapper
 * @date 2023
 * 
 * @copyright Copyright (c) 2023 Purdue eCTF Team
 * 
 */

#include <stdint.h>
#include <sys/types.h>

/*
 * Do not change this file
 */

// Defines location and length of random seed used to initialize PRNG
#define RANDOM_SEED 0x210
#define RANDOM_SEED_LEN 4

// Defines location and length of fob key
#define FOB_KEY 0x200
#define FOB_KEY_LEN 0x10

// Defines location and length of car key
#define CAR_KEY 0x200
#define CAR_KEY_LEN 0x10

// Defines location and length of fob secret salt used to hash the pairing pin
#define FOB_SECRET_SALT 0x300
#define FOB_SECRET_SALT_LEN 26

// Defines location and length of car secret salt used to enable features
#define CAR_SECRET_SALT 0x300
#define CAR_SECRET_SALT_LEN 48

// Defines location and length of fob pairing pin hash
#define FOB_PIN_HASH 0x214
#define FOB_PIN_HASH_LEN 0x20

// Defines location and length of the fob state
#define FOB_STATE 0x234
#define FOB_STATE_LEN 0x4

// Defines location and length of the fob feature data
#define FOB_FEATURE_DATA 0x238
#define FOB_FEATURE_DATA_LEN 1 + (16 * 3)

// Defines location and length of the car feature keys
#define FEATURE_KEY_1_HASH 0x214
#define FEATURE_KEY_1_HASH_LEN 0x20

#define FEATURE_KEY_2_HASH 0x234
#define FEATURE_KEY_2_HASH_LEN 0x20

#define FEATURE_KEY_3_HASH 0x254
#define FEATURE_KEY_3_HASH_LEN 0x20