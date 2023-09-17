/**
 * @file firmware.h
 * @author Spartan State Security Team
 * @brief File that contains header information for the firmware of the Secure Car device
 * @date 2023
 * 
 * This source file is part of our designed system
 * for MITRE's 2023 Embedded System CTF (eCTF).
 */

#ifndef CAR_FIRMWARE_H
#define CAR_FIRMWARE_H

#include "sb_all.h"

/*** Macro Definitions ***/
// Definitions for unlock message location in EEPROM
#define UNLOCK_EEPROM_LOC 0x7C0
#define UNLOCK_EEPROM_SIZE 64

// Features Information
#define NUM_FEATURES 3
#define FEATURE_END UNLOCK_EEPROM_LOC
#define FEATURE_SIZE 64

// Entropy
#define ENTROPY_FLASH 0x3FC00

// System Information
#define SPEED 80000000
#define BAUD 115200
#define ENDIAN 1

/*** Structure definitions ***/
// Defines a struct for a packaged feature
typedef sb_sw_signature_t PACKAGE;

// Defines a struct for the challenge in the challenge-response mechanism
typedef struct {
  uint8_t data[64];
} CHALLENGE;

// Defines a struct for the response in the challenge-response mechanism
typedef struct {
  sb_sw_signature_t unlock;
  PACKAGE feature[3];
} RESPONSE;

// Defines a struct for storing the car data
typedef struct {
  sb_sw_public_t host_pubkey;
  sb_sw_public_t car_pubkey;
} CAR_DATA;

// Defines a struct for storing entropy in flash
typedef struct {
  uint8_t data[0x400];
} ENTROPY;

/*** Function definitions ***/
// Core Functions
bool tryUnlock(void);
bool startCar(RESPONSE *response);
bool unlockCar(void);

// Security Functions
bool gen_challenge(CHALLENGE *challenge);
bool verify_response(CHALLENGE *challenge, RESPONSE *response);

// Helper Functions
bool init_drbg(void);

#endif