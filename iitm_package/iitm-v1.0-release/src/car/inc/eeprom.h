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
 * Returns CAR ID
 */
uint8_t retrieve_carid(void);


/**
 * @brief 
 * Unlock Secret - Secret read from EEPROM: SECRET_FLAG_LEN bytes
 * @param secret: Secret value is stored here 
 */
void retrieve_unlock_secret(uint8_t* secret);

/**
 * @brief 
 * Feature 1 Secret - Secret read from EEPROM: SECRET_FLAG_LEN bytes
 * @param secret: Secret value is stored here 
 */
void retrieve_feature1_secret(uint8_t* secret);

/**
 * @brief 
 * Feature 2 Secret - Secret read from EEPROM: SECRET_FLAG_LEN bytes
 * @param secret: Secret value is stored here 
 */
void retrieve_feature2_secret(uint8_t* secret);

/**
 * @brief 
 * Feature 3 Secret - Secret read from EEPROM: SECRET_FLAG_LEN bytes
 * @param secret: Secret value is stored here 
 */
void retrieve_feature3_secret(uint8_t* secret);


#endif