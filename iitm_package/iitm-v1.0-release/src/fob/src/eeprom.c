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
#include "driverlib/uart.h"

#include "eeprom.h"

#include "secrets.h"

#define NONCELEN 16                             //Nonce length used in ASCON
#define AUTHENTICATED_TAG_LEN 16                //Authenticated Tag length used in ASCON
#define KEYLEN 16                               //Key length used in ASCON
#define SECRET_FLAG_LEN 64                      //Secret Flag length

#define PAIRINGPINLEN 6                         //Length of Pairing PIN
#define CARIDLEN 1                              //Length of CARID
#define FEATUREIDLEN 1                          //Length of Feature ID
#define FEATURE1LEN FEATUREIDLEN                //Length of Feature ID
#define FEATURE2LEN FEATUREIDLEN                //Length of Feature ID
#define FEATURE3LEN FEATUREIDLEN                //Length of Feature ID
#define FEATURECHECKLEN 1                       //Length of Feature ID List
#define TOKEN_LEN 16                            //Token Length used in encryptions

#define TOTAL_UNLOCK_KEYS 12                    //Total number of keys
#define PAIRED_BOOL 0b01111111

#define PAIRED_BOOL_START 0x40                  //Starting address of pair_bool
#define CARID_START 0x80                        //Starting address of CAR_ID
#define CARPIN_START 0xC0                       //Starting address of pairing pin
#define FEATURE_INFO_START 0x100                //Starting address of feature info
#define PACKAGEKEY_START 0x140                  //Starting address of package key
#define KEYPAIR_START 0x180                     //Starting address of unlock key

#define EEPROM_BLOCK_SIZE 64


/**
 * @brief 
 * Erase stack data. Zeroes array values
 */
inline __attribute__((__always_inline__)) void erase_stack_data(uint8_t *start_add, uint32_t data_len){
    for(uint32_t i=0; i < data_len; i++){
        start_add[i] = 0;
    }
}

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

    //Locking Paired_Bool
    EEPROMBlockUnlock(PAIRED_BOOL_START/EEPROM_BLOCK_SIZE, &pairedbool_password, 1);
    EEPROMBlockProtectSet(PAIRED_BOOL_START/EEPROM_BLOCK_SIZE, EEPROM_PROT_NA_LNA_URW);
    EEPROMBlockPasswordSet(PAIRED_BOOL_START/EEPROM_BLOCK_SIZE, &pairedbool_password, 1);
    EEPROMBlockLock(PAIRED_BOOL_START/EEPROM_BLOCK_SIZE);

    //Locking Car ID
    EEPROMBlockUnlock(CARID_START/EEPROM_BLOCK_SIZE, &carid_password, 1);
    EEPROMBlockProtectSet(CARID_START/EEPROM_BLOCK_SIZE, EEPROM_PROT_NA_LNA_URW);
    EEPROMBlockPasswordSet(CARID_START/EEPROM_BLOCK_SIZE, &carid_password, 1);
    EEPROMBlockLock(CARID_START/EEPROM_BLOCK_SIZE);

    //Locking Pairing pin
    EEPROMBlockUnlock(CARPIN_START/EEPROM_BLOCK_SIZE, &pairingpin_password, 1);
    EEPROMBlockProtectSet(CARPIN_START/EEPROM_BLOCK_SIZE, EEPROM_PROT_NA_LNA_URW);
    EEPROMBlockPasswordSet(CARPIN_START/EEPROM_BLOCK_SIZE, &pairingpin_password, 1);
    EEPROMBlockLock(CARPIN_START/EEPROM_BLOCK_SIZE);

    //Locking Feature Info
    EEPROMBlockUnlock(FEATURE_INFO_START/EEPROM_BLOCK_SIZE, &featureinfo_password, 1);
    EEPROMBlockProtectSet(FEATURE_INFO_START/EEPROM_BLOCK_SIZE, EEPROM_PROT_NA_LNA_URW);
    EEPROMBlockPasswordSet(FEATURE_INFO_START/EEPROM_BLOCK_SIZE, &featureinfo_password, 1);
    EEPROMBlockLock(FEATURE_INFO_START/EEPROM_BLOCK_SIZE);

    //Locking package key
    EEPROMBlockUnlock(PACKAGEKEY_START/EEPROM_BLOCK_SIZE, &package_key_password, 1);
    EEPROMBlockProtectSet(PACKAGEKEY_START/EEPROM_BLOCK_SIZE, EEPROM_PROT_NA_LNA_URW);
    EEPROMBlockPasswordSet(PACKAGEKEY_START/EEPROM_BLOCK_SIZE, &package_key_password, 1);
    EEPROMBlockLock(PACKAGEKEY_START/EEPROM_BLOCK_SIZE);

    //Locking unlock key
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

}


/**
 * @brief 
 * Given which Key Set: {0....TOTAL_UNLOCK_KEYS}: 'key_id', whether it is 0 or 1: 'encrypt_or_decrypt', 
 * Unlock EEPROM Block, Get the key of size "KEYLEN bytes" from EEPROM and copy it in the 'key' array
 * Locks EEPROM Block before returning
 * @param key_id :  {0....TOTAL_UNLOCK_KEYS}
 * @param encrypt_or_decrypt : 0 or 1
 * @param key : keys are retreived and stored here
 */
void retrieve_unlockkey(uint8_t key_id, uint8_t encrypt_or_decrypt, uint8_t* key){

    if (key_id >= TOTAL_UNLOCK_KEYS)
        return;

    // retreive keys from eeprom: eepromread
    EEPROMBlockUnlock(KEYPAIR_START/EEPROM_BLOCK_SIZE, &unlock_key_password, 1);
    EEPROMBlockUnlock((KEYPAIR_START + EEPROM_BLOCK_SIZE)/EEPROM_BLOCK_SIZE, &unlock_key_password, 1);
    EEPROMBlockUnlock((KEYPAIR_START + 2*EEPROM_BLOCK_SIZE)/EEPROM_BLOCK_SIZE, &unlock_key_password, 1);
    EEPROMBlockUnlock((KEYPAIR_START + 3*EEPROM_BLOCK_SIZE)/EEPROM_BLOCK_SIZE, &unlock_key_password, 1);
    EEPROMBlockUnlock((KEYPAIR_START + 4*EEPROM_BLOCK_SIZE)/EEPROM_BLOCK_SIZE, &unlock_key_password, 1);
    EEPROMBlockUnlock((KEYPAIR_START + 5*EEPROM_BLOCK_SIZE)/EEPROM_BLOCK_SIZE, &unlock_key_password, 1);
    uint32_t offset = KEYPAIR_START + (2 * key_id + encrypt_or_decrypt)* KEYLEN;
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
 * Given which Key Set: {0....TOTAL_UNLOCK_KEYS}: 'key_id', whether it is 0 or 1: 'encrypt_or_decrypt', 
 * Unlock EEPROM Block, Store the key from array 'key' of size "KEYLEN" bytes into EEPROM.
 * Locks EEPROM block before returning
 * @param key_id :  {0....TOTAL_UNLOCK_KEYS}
 * @param encrypt_or_decrypt : 0 or 1
 * @param key : values stored here are stored in EEPROM
 */
void store_unlockkey(uint8_t key_id, uint8_t encrypt_or_decrypt, uint8_t* key){

    if (key_id >= TOTAL_UNLOCK_KEYS)
        return;

    EEPROMBlockUnlock(KEYPAIR_START/EEPROM_BLOCK_SIZE, &unlock_key_password, 1);
    EEPROMBlockUnlock((KEYPAIR_START + EEPROM_BLOCK_SIZE)/EEPROM_BLOCK_SIZE, &unlock_key_password, 1);
    EEPROMBlockUnlock((KEYPAIR_START + 2*EEPROM_BLOCK_SIZE)/EEPROM_BLOCK_SIZE, &unlock_key_password, 1);
    EEPROMBlockUnlock((KEYPAIR_START + 3*EEPROM_BLOCK_SIZE)/EEPROM_BLOCK_SIZE, &unlock_key_password, 1);
    EEPROMBlockUnlock((KEYPAIR_START + 4*EEPROM_BLOCK_SIZE)/EEPROM_BLOCK_SIZE, &unlock_key_password, 1);
    EEPROMBlockUnlock((KEYPAIR_START + 5*EEPROM_BLOCK_SIZE)/EEPROM_BLOCK_SIZE, &unlock_key_password, 1);
    uint32_t offset = KEYPAIR_START + (2 * key_id + encrypt_or_decrypt)* KEYLEN;
    EEPROMProgram((uint32_t *)key, offset, KEYLEN);
    EEPROMBlockLock(KEYPAIR_START/EEPROM_BLOCK_SIZE);
    EEPROMBlockLock((KEYPAIR_START + EEPROM_BLOCK_SIZE)/EEPROM_BLOCK_SIZE);
    EEPROMBlockLock((KEYPAIR_START + 2*EEPROM_BLOCK_SIZE)/EEPROM_BLOCK_SIZE);
    EEPROMBlockLock((KEYPAIR_START + 3*EEPROM_BLOCK_SIZE)/EEPROM_BLOCK_SIZE);
    EEPROMBlockLock((KEYPAIR_START + 4*EEPROM_BLOCK_SIZE)/EEPROM_BLOCK_SIZE);
    EEPROMBlockLock((KEYPAIR_START + 5*EEPROM_BLOCK_SIZE)/EEPROM_BLOCK_SIZE);
}


/**
 * @brief 
 * Unlocks the EEPROM block and gets the package key of size "KEYLEN bytes" from EEPROM and copy it in the 'key' array
 * Locks EEPROM block before returning
 * @param key : keys are retreived from EEPROM and stored here
 */
void retrieve_packagekey(uint8_t* key){

    EEPROMBlockUnlock(PACKAGEKEY_START/EEPROM_BLOCK_SIZE, &package_key_password, 1);
    uint32_t offset = PACKAGEKEY_START;
    EEPROMRead((uint32_t *)key, offset, KEYLEN);
    EEPROMBlockLock(PACKAGEKEY_START/EEPROM_BLOCK_SIZE);

}


/**
 * @brief 
 * Unlocks the EEPROM block, Store the package key from array 'key' of size "KEYLEN" bytes into EEPROM.
 * Locks EEPROM block before returning
 * @param key : values stored here are stored in EEPROM
 */
void store_packagekey(uint8_t* key){

    EEPROMBlockUnlock(PACKAGEKEY_START/EEPROM_BLOCK_SIZE, &package_key_password, 1);
    uint32_t offset = PACKAGEKEY_START;
    EEPROMProgram((uint32_t *)key, offset, KEYLEN);
    EEPROMBlockLock(PACKAGEKEY_START/EEPROM_BLOCK_SIZE);
}

/**
 * @brief 
 * Return true if the fob is paired 
 * 
 * Unlocks the EEPROM block, Retrieves data which says whether fob is paired or not
 * Locks the EEPROM block before returning
 */
bool retrieve_pair_bool(){
    uint32_t offset = PAIRED_BOOL_START;
    uint8_t data[4];
    EEPROMBlockUnlock(PAIRED_BOOL_START/EEPROM_BLOCK_SIZE, &pairedbool_password, 1);
    EEPROMRead((uint32_t *)data, offset, 4);
    EEPROMBlockLock(PAIRED_BOOL_START/EEPROM_BLOCK_SIZE);
    return (data[0] == PAIRED_BOOL); 
}

/**
 * @brief 
 * Writes true when the unpaired fob becomes paired
 * 
 * Unlocks the EEPROM block, Stores data which says whether fob is paired or not
 * Locks the EEPROM block before returning
 * 
 * @param value: stores value which determines whether fob is paired or not 
 */
void store_pair_bool(bool value){ 
    uint8_t data[4];
    if(value){
        data[0] = PAIRED_BOOL;
    }
    else data[0] = !PAIRED_BOOL;
    uint32_t offset = PAIRED_BOOL_START;
    EEPROMBlockUnlock(PAIRED_BOOL_START/EEPROM_BLOCK_SIZE, &pairedbool_password, 1);
    EEPROMProgram((uint32_t *)data, offset, 4);
    EEPROMBlockLock(PAIRED_BOOL_START/EEPROM_BLOCK_SIZE);
}

/**
 * @brief 
 * Unlocks the EEPROM block, Get the pairing_pin  of size "PAIRINGPINLEN" bytes from EEPROM and copy it in the 'pairing_pin' array
 * Locks the EEPROM block before returning
 * 
 * @param pairing_pin: pairing_pin are retreived from EEPROM and stored here
 */
void retrieve_pair_pin(uint8_t* pairing_pin){
    uint8_t data[8];
    uint32_t offset = CARPIN_START;
    EEPROMBlockUnlock(CARPIN_START/EEPROM_BLOCK_SIZE, &pairingpin_password, 1);
    EEPROMRead((uint32_t *)data, offset, 8);
    EEPROMBlockLock(CARPIN_START/EEPROM_BLOCK_SIZE);
    for(int i=0; i<PAIRINGPINLEN; i++) pairing_pin[i] = data[i];
    erase_stack_data(data, 8);
}


/**
 * @brief 
 * Unlocks the EEPROM block, Store the pairing_pin  of size "PAIRINGPINLEN" bytes into EEPROM from 'pairing_pin' array
 * Locks the EEPROM block before returning
 * 
 * @param pairing_pin: values stored here are stored in EEPROM
 */
void store_pair_pin(uint8_t* pairing_pin){
    uint8_t data[8] = "00000000";  
    uint32_t offset = CARPIN_START;
    for(int i=0; i<PAIRINGPINLEN; i++) {
            data[i] = pairing_pin[i];
    }
    EEPROMBlockUnlock(CARPIN_START/EEPROM_BLOCK_SIZE, &pairingpin_password, 1);
    EEPROMProgram((uint32_t *)data, offset, 8);
    EEPROMBlockLock(CARPIN_START/EEPROM_BLOCK_SIZE);
    erase_stack_data(data, 8);
}


/**
 * @brief 
 * Returns CAR ID
 * 
 * Unlocks the EEPROM block, CAR_ID read from EEPROM: CARIDLEN bytes
 * Locks the EEPROM block before returning
 */
uint8_t retrieve_carid(){
    uint8_t data[4];
    uint32_t offset = CARID_START;
    EEPROMBlockUnlock(CARID_START/EEPROM_BLOCK_SIZE, &carid_password, 1);
    EEPROMRead((uint32_t *)data, offset, 4);
    EEPROMBlockLock(CARID_START/EEPROM_BLOCK_SIZE);
    return (uint8_t)data[0];
}

/**
 * @brief 
 * Unlocks the EEPROM block, Stores the CAR ID of size CARIDLEN into EEPROM
 * Locks the EEPROM block before returning
 * @param carid: values stored here are stored in EEPROM
 */
void store_carid(uint8_t carid){ 
    uint8_t data[4] = "0000";
    data[0] = (uint8_t)carid;
    uint32_t offset = CARID_START;
    EEPROMBlockUnlock(CARID_START/EEPROM_BLOCK_SIZE, &carid_password, 1);
    EEPROMProgram((uint32_t *)data, offset, 4);
    EEPROMBlockLock(CARID_START/EEPROM_BLOCK_SIZE);
}



/**
 * @brief 
 * Returns Feature ID 1
 * 
 * Unlocks the EEPROM block, FEATUREID1 read from EEPROM: FEATURE1LEN bytes
 * Locks the EEPROM block before returning
 */
uint8_t retrieve_feature1(){
    uint8_t data[4];
    uint32_t offset = FEATURE_INFO_START;
    EEPROMBlockUnlock(FEATURE_INFO_START/EEPROM_BLOCK_SIZE, &featureinfo_password, 1);
    EEPROMRead((uint32_t *)data, offset, 4);
    EEPROMBlockLock(FEATURE_INFO_START/EEPROM_BLOCK_SIZE);
    return (uint8_t)data[0];
}


/**
 * @brief 
 * Unlocks the EEPROM block, Stores the Feature ID 1 of size FEATURE1LEN into EEPROM
 * Locks the EEPROM block before returning
 */
void store_feature1(uint8_t feature1id){ 
    uint8_t data[4];
    uint32_t offset = FEATURE_INFO_START;
    EEPROMBlockUnlock(FEATURE_INFO_START/EEPROM_BLOCK_SIZE, &featureinfo_password, 1);
    EEPROMRead((uint32_t *)data, offset, 4);
    data[0] = (uint8_t)feature1id;
    data[3] ^= 0b00000100 ;
    EEPROMProgram((uint32_t *)data, offset, 4);
    EEPROMBlockLock(FEATURE_INFO_START/EEPROM_BLOCK_SIZE);
}

/**
 * @brief 
 * Returns Feature ID 2
 * 
 * Unlocks the EEPROM block, FEATUREID2 read from EEPROM: FEATURE2LEN bytes
 * Locks the EEPROM block before returning
 */
uint8_t retrieve_feature2(){
    uint8_t data[4];
    uint32_t offset = FEATURE_INFO_START;
    EEPROMBlockUnlock(FEATURE_INFO_START/EEPROM_BLOCK_SIZE, &featureinfo_password, 1);    
    EEPROMRead((uint32_t *)data, offset, 4);
    EEPROMBlockLock(FEATURE_INFO_START/EEPROM_BLOCK_SIZE);
    return (uint8_t)data[1];
}

/**
 * @brief 
 * Unlocks the EEPROM block, Stores the Feature ID 2 of size FEATURE1LEN into EEPROM
 * Locks the EEPROM block before returning
 */
void store_feature2(uint8_t feature2id){ 
    uint8_t data[4];
    uint32_t offset = FEATURE_INFO_START;
    EEPROMBlockUnlock(FEATURE_INFO_START/EEPROM_BLOCK_SIZE, &featureinfo_password, 1);    
    EEPROMRead((uint32_t *)data, offset, 4);
    data[1] = (uint8_t)feature2id;
    data[3] ^= 0b00000010 ;
    EEPROMProgram((uint32_t *)data, offset, 4);
    EEPROMBlockLock(FEATURE_INFO_START/EEPROM_BLOCK_SIZE);
}

/**
 * @brief 
 * Returns Feature ID 3
 * 
 * Unlocks the EEPROM block, FEATUREID3 read from EEPROM: FEATURE3LEN bytes
 * Locks the EEPROM block before returning
 */
uint8_t retrieve_feature3(){
    uint8_t data[4];
    uint32_t offset = FEATURE_INFO_START;
    EEPROMBlockUnlock(FEATURE_INFO_START/EEPROM_BLOCK_SIZE, &featureinfo_password, 1);    
    EEPROMRead((uint32_t *)data, offset, 4);
    EEPROMBlockLock(FEATURE_INFO_START/EEPROM_BLOCK_SIZE);
    return (uint8_t)data[2];
}

/**
 * @brief 
 * Unlocks the EEPROM block, Stores the Feature ID 3 of size FEATURE1LEN into EEPROM
 * Locks the EEPROM block before returning
 */
void store_feature3(uint8_t feature3id){ 
    uint8_t data[4];
    uint32_t offset = FEATURE_INFO_START;
    EEPROMBlockUnlock(FEATURE_INFO_START/EEPROM_BLOCK_SIZE, &featureinfo_password, 1);    
    EEPROMRead((uint32_t *)data, offset, 4);
    data[2] = (uint8_t)feature3id;
    data[3] ^= 0b00000001 ;
    EEPROMProgram((uint32_t *)data, offset, 4);
    EEPROMBlockLock(FEATURE_INFO_START/EEPROM_BLOCK_SIZE);
}

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
uint8_t retrieve_featurelist(){
    uint8_t data[4];
    uint32_t offset = FEATURE_INFO_START;
    EEPROMBlockUnlock(FEATURE_INFO_START/EEPROM_BLOCK_SIZE, &featureinfo_password, 1);    
    EEPROMRead((uint32_t *)data, offset, 4);
    EEPROMBlockLock(FEATURE_INFO_START/EEPROM_BLOCK_SIZE);
    return (uint8_t)data[3];
}

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
void store_featurelist(uint8_t featurelist){ 
    uint8_t data[4];
    uint32_t offset = FEATURE_INFO_START;
    EEPROMBlockUnlock(FEATURE_INFO_START/EEPROM_BLOCK_SIZE, &featureinfo_password, 1);    
    EEPROMRead((uint32_t *)data, offset, 4);
    data[3] = (uint8_t)featurelist;
    EEPROMProgram((uint32_t *)data, offset, 4);
    EEPROMBlockLock(FEATURE_INFO_START/EEPROM_BLOCK_SIZE);
}
