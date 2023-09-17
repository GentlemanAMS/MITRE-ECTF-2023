#include <stdbool.h>
#include <stdint.h>
#define PART_TM4C123GH6PM 1

#include "inc/hw_ints.h"
#include "inc/hw_gpio.h"
#include "inc/hw_memmap.h"

#include "driverlib/eeprom.h"
#include "driverlib/gpio.h"
#include "driverlib/pin_map.h"
#include "driverlib/sysctl.h"

#include "eeprom.h"
#include "secrets.h"

#define NONCELEN 16                             //Nonce length used in ASCON
#define AUTHENTICATED_TAG_LEN 16                //Authenticated Tag length used in ASCON
#define KEYLEN 16                               //Key length used in ASCON
#define SECRET_FLAG_LEN 64                      //Secret Flag length

#define CARIDLEN 1                              //Length of CARID
#define FEATUREIDLEN 1                          //Length of Feature ID
#define FEATURE1LEN FEATUREIDLEN                //Length of Feature ID
#define FEATURE2LEN FEATUREIDLEN                //Length of Feature ID
#define FEATURE3LEN FEATUREIDLEN                //Length of Feature ID
#define FEATURECHECKLEN 1                       //Length of Feature ID List
#define TOKEN_LEN 16                            //Token Length used in encryptions

#define TOTAL_UNLOCK_KEYS 12                    //Total number of keys

#define CAR_ID 0x40
#define KEYPAIR_START 0x80
#define UNLOCK_MESSAGE_START 0x7c0
#define FEATURE1_MESSAGE_START 0x780
#define FEATURE2_MESSAGE_START 0x740
#define FEATURE3_MESSAGE_START 0x700

#define EEPROM_BLOCK_SIZE 64


/**
 * @brief 
 * EEPROM Initialization
 * 
 * Sets up EEPROM.
 * Locks the EEPROM Blocks with password
 */
void eeprom_init(void){
    SysCtlPeripheralEnable(SYSCTL_PERIPH_EEPROM0);
    EEPROMInit();

    EEPROMBlockUnlock(KEYPAIR_START/EEPROM_BLOCK_SIZE, &unlock_key_password, 1);
    EEPROMBlockProtectSet(KEYPAIR_START/EEPROM_BLOCK_SIZE, EEPROM_PROT_NA_LNA_URW);
    EEPROMBlockPasswordSet(KEYPAIR_START/EEPROM_BLOCK_SIZE, &unlock_key_password, 1);
    EEPROMBlockLock(KEYPAIR_START/EEPROM_BLOCK_SIZE);

    EEPROMBlockUnlock((KEYPAIR_START + EEPROM_BLOCK_SIZE)/EEPROM_BLOCK_SIZE, &unlock_key_password, 1);
    EEPROMBlockProtectSet((KEYPAIR_START + EEPROM_BLOCK_SIZE)/EEPROM_BLOCK_SIZE, EEPROM_PROT_NA_LNA_URW);
    EEPROMBlockPasswordSet((KEYPAIR_START + EEPROM_BLOCK_SIZE)/EEPROM_BLOCK_SIZE, &unlock_key_password, 1);
    EEPROMBlockLock((KEYPAIR_START + EEPROM_BLOCK_SIZE)/EEPROM_BLOCK_SIZE);

    EEPROMBlockUnlock((KEYPAIR_START + 2*EEPROM_BLOCK_SIZE)/EEPROM_BLOCK_SIZE, &unlock_key_password, 1);
    EEPROMBlockProtectSet((KEYPAIR_START + 2*EEPROM_BLOCK_SIZE)/EEPROM_BLOCK_SIZE, EEPROM_PROT_NA_LNA_URW);
    EEPROMBlockPasswordSet((KEYPAIR_START + 2*EEPROM_BLOCK_SIZE)/EEPROM_BLOCK_SIZE, &unlock_key_password, 1);
    EEPROMBlockLock((KEYPAIR_START + 2*EEPROM_BLOCK_SIZE)/EEPROM_BLOCK_SIZE);

    EEPROMBlockUnlock((KEYPAIR_START + 3*EEPROM_BLOCK_SIZE)/EEPROM_BLOCK_SIZE, &unlock_key_password, 1);
    EEPROMBlockProtectSet((KEYPAIR_START + 3*EEPROM_BLOCK_SIZE)/EEPROM_BLOCK_SIZE, EEPROM_PROT_NA_LNA_URW);
    EEPROMBlockPasswordSet((KEYPAIR_START + 3*EEPROM_BLOCK_SIZE)/EEPROM_BLOCK_SIZE, &unlock_key_password, 1);
    EEPROMBlockLock((KEYPAIR_START + 3*EEPROM_BLOCK_SIZE)/EEPROM_BLOCK_SIZE);

    EEPROMBlockUnlock((KEYPAIR_START + 4*EEPROM_BLOCK_SIZE)/EEPROM_BLOCK_SIZE, &unlock_key_password, 1);
    EEPROMBlockProtectSet((KEYPAIR_START + 4*EEPROM_BLOCK_SIZE)/EEPROM_BLOCK_SIZE, EEPROM_PROT_NA_LNA_URW);
    EEPROMBlockPasswordSet((KEYPAIR_START + 4*EEPROM_BLOCK_SIZE)/EEPROM_BLOCK_SIZE, &unlock_key_password, 1);
    EEPROMBlockLock((KEYPAIR_START + 4*EEPROM_BLOCK_SIZE)/EEPROM_BLOCK_SIZE);

    EEPROMBlockUnlock((KEYPAIR_START + 5*EEPROM_BLOCK_SIZE)/EEPROM_BLOCK_SIZE, &unlock_key_password, 1);
    EEPROMBlockProtectSet((KEYPAIR_START + 5*EEPROM_BLOCK_SIZE)/EEPROM_BLOCK_SIZE, EEPROM_PROT_NA_LNA_URW);
    EEPROMBlockPasswordSet((KEYPAIR_START + 5*EEPROM_BLOCK_SIZE)/EEPROM_BLOCK_SIZE, &unlock_key_password, 1);
    EEPROMBlockLock((KEYPAIR_START + 5*EEPROM_BLOCK_SIZE)/EEPROM_BLOCK_SIZE);


    EEPROMBlockUnlock(UNLOCK_MESSAGE_START/EEPROM_BLOCK_SIZE, &unlock_secret_password, 1);
    EEPROMBlockProtectSet(UNLOCK_MESSAGE_START/EEPROM_BLOCK_SIZE, EEPROM_PROT_NA_LNA_URW);
    EEPROMBlockPasswordSet(UNLOCK_MESSAGE_START/EEPROM_BLOCK_SIZE, &unlock_secret_password, 1);
    EEPROMBlockLock(UNLOCK_MESSAGE_START/EEPROM_BLOCK_SIZE);

    EEPROMBlockUnlock(FEATURE1_MESSAGE_START/EEPROM_BLOCK_SIZE, &feature1_secret_password, 1);
    EEPROMBlockProtectSet(FEATURE1_MESSAGE_START/EEPROM_BLOCK_SIZE, EEPROM_PROT_NA_LNA_URW);
    EEPROMBlockPasswordSet(FEATURE1_MESSAGE_START/EEPROM_BLOCK_SIZE, &feature1_secret_password, 1);
    EEPROMBlockLock(FEATURE1_MESSAGE_START/EEPROM_BLOCK_SIZE);

    EEPROMBlockUnlock(FEATURE2_MESSAGE_START/EEPROM_BLOCK_SIZE, &feature2_secret_password, 1);
    EEPROMBlockProtectSet(FEATURE2_MESSAGE_START/EEPROM_BLOCK_SIZE, EEPROM_PROT_NA_LNA_URW);
    EEPROMBlockPasswordSet(FEATURE2_MESSAGE_START/EEPROM_BLOCK_SIZE, &feature2_secret_password, 1);
    EEPROMBlockLock(FEATURE2_MESSAGE_START/EEPROM_BLOCK_SIZE);

    EEPROMBlockUnlock(FEATURE3_MESSAGE_START/EEPROM_BLOCK_SIZE, &feature3_secret_password, 1);
    EEPROMBlockProtectSet(FEATURE3_MESSAGE_START/EEPROM_BLOCK_SIZE, EEPROM_PROT_NA_LNA_URW);
    EEPROMBlockPasswordSet(FEATURE3_MESSAGE_START/EEPROM_BLOCK_SIZE, &feature3_secret_password, 1);
    EEPROMBlockLock(FEATURE3_MESSAGE_START/EEPROM_BLOCK_SIZE);
}

/**
 * @brief 
 * Given which Key Set: {0....TOTAL_UNLOCK_KEYS}: 'key_id', whether it is 0 or 1: 'encrypt_or_decrypt', 
 * Unlock EEPROM Block, Get the key of size "KEYLEN bytes" from EEPROM and copy it in the 'key' array
 * Locks EEPROM Block before returning
 */
void retrieve_unlockkey(uint8_t key_id, uint8_t encrypt_or_decrypt, uint8_t* key){

    if (key_id >= TOTAL_UNLOCK_KEYS)
        return;
    
    EEPROMBlockUnlock(KEYPAIR_START/EEPROM_BLOCK_SIZE, &unlock_key_password, 1);
    EEPROMBlockUnlock((KEYPAIR_START + EEPROM_BLOCK_SIZE)/EEPROM_BLOCK_SIZE, &unlock_key_password, 1);
    EEPROMBlockUnlock((KEYPAIR_START + 2*EEPROM_BLOCK_SIZE)/EEPROM_BLOCK_SIZE, &unlock_key_password, 1);
    EEPROMBlockUnlock((KEYPAIR_START + 3*EEPROM_BLOCK_SIZE)/EEPROM_BLOCK_SIZE, &unlock_key_password, 1);
    EEPROMBlockUnlock((KEYPAIR_START + 4*EEPROM_BLOCK_SIZE)/EEPROM_BLOCK_SIZE, &unlock_key_password, 1);
    EEPROMBlockUnlock((KEYPAIR_START + 5*EEPROM_BLOCK_SIZE)/EEPROM_BLOCK_SIZE, &unlock_key_password, 1);
    int32_t offset = KEYPAIR_START + (2 * key_id + encrypt_or_decrypt)* KEYLEN;
    EEPROMRead((uint32_t*)key, offset, KEYLEN);
    EEPROMBlockLock(KEYPAIR_START/EEPROM_BLOCK_SIZE);
    EEPROMBlockLock((KEYPAIR_START + EEPROM_BLOCK_SIZE)/EEPROM_BLOCK_SIZE);
    EEPROMBlockLock((KEYPAIR_START + 2*EEPROM_BLOCK_SIZE)/EEPROM_BLOCK_SIZE);
    EEPROMBlockLock((KEYPAIR_START + 3*EEPROM_BLOCK_SIZE)/EEPROM_BLOCK_SIZE);
    EEPROMBlockLock((KEYPAIR_START + 4*EEPROM_BLOCK_SIZE)/EEPROM_BLOCK_SIZE);
    EEPROMBlockLock((KEYPAIR_START + 5*EEPROM_BLOCK_SIZE)/EEPROM_BLOCK_SIZE);
}

/**
 * @brief 
 * Returns CAR ID
 */
uint8_t retrieve_carid(){
    uint8_t data [4];
    EEPROMRead((uint32_t*)data, CAR_ID, 4);
    return data[0];
}

/**
 * @brief 
 * Unlock Secret - Secret read from EEPROM: SECRET_FLAG_LEN bytes
 * @param secret: Secret value is stored here 
 */
void retrieve_unlock_secret(uint8_t* secret){
    EEPROMBlockUnlock(UNLOCK_MESSAGE_START/EEPROM_BLOCK_SIZE, &unlock_secret_password, 1);
    EEPROMRead((uint32_t *)secret, UNLOCK_MESSAGE_START, SECRET_FLAG_LEN);
    EEPROMBlockLock(UNLOCK_MESSAGE_START/EEPROM_BLOCK_SIZE);
}

/**
 * @brief 
 * Feature 1 Secret - Secret read from EEPROM: SECRET_FLAG_LEN bytes
 * @param secret: Secret value is stored here 
 */
void retrieve_feature1_secret(uint8_t* secret){
    EEPROMBlockUnlock(FEATURE1_MESSAGE_START/EEPROM_BLOCK_SIZE, &feature1_secret_password, 1);
    EEPROMRead((uint32_t *)secret, FEATURE1_MESSAGE_START, SECRET_FLAG_LEN);
    EEPROMBlockLock(FEATURE1_MESSAGE_START/EEPROM_BLOCK_SIZE);
}

/**
 * @brief 
 * Feature 2 Secret - Secret read from EEPROM: SECRET_FLAG_LEN bytes
 * @param secret: Secret value is stored here 
 */
void retrieve_feature2_secret(uint8_t* secret){
    EEPROMBlockUnlock(FEATURE2_MESSAGE_START/EEPROM_BLOCK_SIZE, &feature2_secret_password, 1);
    EEPROMRead((uint32_t *)secret, FEATURE2_MESSAGE_START, SECRET_FLAG_LEN);
    EEPROMBlockLock(FEATURE2_MESSAGE_START/EEPROM_BLOCK_SIZE);
}

/**
 * @brief 
 * Feature 3 Secret - Secret read from EEPROM: SECRET_FLAG_LEN bytes
 * @param secret: Secret value is stored here 
 */
void retrieve_feature3_secret(uint8_t* secret){
    EEPROMBlockUnlock(FEATURE3_MESSAGE_START/EEPROM_BLOCK_SIZE, &feature3_secret_password, 1);
    EEPROMRead((uint32_t *)secret, FEATURE3_MESSAGE_START, SECRET_FLAG_LEN);
    EEPROMBlockLock(FEATURE3_MESSAGE_START/EEPROM_BLOCK_SIZE);
}
