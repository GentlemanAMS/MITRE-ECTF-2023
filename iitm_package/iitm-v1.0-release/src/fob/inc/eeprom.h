#ifndef EEPROM_PROTECTION_H
#define EEPROM_PROTECTION_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * @brief 
 * EEPROM Initialization
 * 
 * Sets up EEPROM.
 * Locks the EEPROM Blocks with password
 */
void eeprom_init(void);

/**
 * @brief 
 * Given which Key Set: {0....TOTAL_UNLOCK_KEYS}: 'key_id', whether it is 0 or 1: 'encrypt_or_decrypt', 
 * Unlock EEPROM Block, Get the key of size "KEYLEN bytes" from EEPROM and copy it in the 'key' array
 * Locks EEPROM Block before returning
 */
void retrieve_unlockkey(uint8_t key_id, uint8_t encrypt_or_decrypt, uint8_t* key);

/**
 * @brief 
 * Given which Key Set: {0....TOTAL_UNLOCK_KEYS}: 'key_id', whether it is 0 or 1: 'encrypt_or_decrypt', 
 * Unlock EEPROM Block, Store the key from array 'key' of size "KEYLEN" bytes into EEPROM.
 * Locks EEPROM block before returning
 */
void store_unlockkey(uint8_t key_id, uint8_t encrypt_or_decrypt, uint8_t* key);

/**
 * @brief 
 * Unlocks the EEPROM block and gets the package key of size "KEYLEN bytes" from EEPROM and copy it in the 'key' array
 * Locks EEPROM block before returning
 */
void retrieve_packagekey(uint8_t* key);

/**
 * @brief 
 * Unlocks the EEPROM block, Store the package key from array 'key' of size "KEYLEN" bytes into EEPROM.
 * Locks EEPROM block before returning
 */
void store_packagekey(uint8_t* key);

/**
 * @brief 
 * Return true if the fob is paired
 * 
 * Unlocks the EEPROM block, Retrieves data which says whether fob is paired or not
 * Locks the EEPROM block before returning
 */
bool retrieve_pair_bool(void);

/**
 * @brief 
 * Writes true when the unpaired fob becomes paired
 * 
 * Unlocks the EEPROM block, Stores data which says whether fob is paired or not
 * Locks the EEPROM block before returning
 */
void store_pair_bool(bool value);

/**
 * @brief 
 * Unlocks the EEPROM block, Get the pairing_pin  of size "PAIRINGPINLEN" bytes from EEPROM and copy it in the 'pairing_pin' array
 * Locks the EEPROM block before returning
 */
void retrieve_pair_pin(uint8_t* pairing_pin);

/**
 * @brief 
 * Unlocks the EEPROM block, Store the pairing_pin  of size "PAIRINGPINLEN" bytes into EEPROM from 'pairing_pin' array
 * Locks the EEPROM block before returning
 */
void store_pair_pin(uint8_t* pairing_pin);

/**
 * @brief 
 * Returns CAR ID
 * 
 * Unlocks the EEPROM block, CAR_ID read from EEPROM: CARIDLEN bytes
 * Locks the EEPROM block before returning
 */
uint8_t retrieve_carid(void);

/**
 * @brief 
 * Unlocks the EEPROM block, Stores the CAR ID of size CARIDLEN into EEPROM
 * Locks the EEPROM block before returning
 */
void store_carid(uint8_t carid);


/**
 * @brief 
 * Returns Feature ID 1
 * 
 * Unlocks the EEPROM block, FEATUREID1 read from EEPROM: FEATURE1LEN bytes
 * Locks the EEPROM block before returning
 */
uint8_t retrieve_feature1(void);

/**
 * @brief 
 * Unlocks the EEPROM block, Stores the Feature ID 1 of size FEATURE1LEN into EEPROM
 * Locks the EEPROM block before returning
 */
void store_feature1(uint8_t feature1id);

/**
 * @brief 
 * Returns Feature ID 2
 * 
 * Unlocks the EEPROM block, FEATUREID2 read from EEPROM: FEATURE2LEN bytes
 * Locks the EEPROM block before returning
 */
uint8_t retrieve_feature2(void);

/**
 * @brief 
 * Unlocks the EEPROM block, Stores the Feature ID 2 of size FEATURE1LEN into EEPROM
 * Locks the EEPROM block before returning
 */
void store_feature2(uint8_t feature2id);

/**
 * @brief 
 * Returns Feature ID 3
 * 
 * Unlocks the EEPROM block, FEATUREID3 read from EEPROM: FEATURE3LEN bytes
 * Locks the EEPROM block before returning
 */
uint8_t retrieve_feature3(void);

/**
 * @brief 
 * Unlocks the EEPROM block, Stores the Feature ID 3 of size FEATURE1LEN into EEPROM
 * Locks the EEPROM block before returning
 */
void store_feature3(uint8_t feature3id);

/**
 * @brief 
 * Unlocks EEPROM
 * Returns which of the three features are active
 * featurelist read from EEPROM: FEATURECHECKLEN bytes
 * Only LSB 3 bits are valid
 * 0b000001xx indicates first feature is valid
 * 0b00000x1x indicates second feature is valid
 * 0b00000xx1 indicates third feature is valid
 * Locks EEPROM
 */
uint8_t retrieve_featurelist(void);

/**
 * @brief 
 * Unlocks EEPROM
 * Stores which of the three features are active
 * featurelist into EEPROM: FEATURECHECKLEN bytes
 * Only LSB 3 bits are valid
 * 0b000001xx indicates first feature is valid
 * 0b00000x1x indicates second feature is valid
 * 0b00000xx1 indicates third feature is valid
 * Locks EEPROM
 */
void store_featurelist(uint8_t featurelist);

#endif