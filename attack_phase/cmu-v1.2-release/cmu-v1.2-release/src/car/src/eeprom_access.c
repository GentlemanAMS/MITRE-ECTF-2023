#include <stdbool.h>

#include "eeprom_access.h"
#include "eeprom.h"
#include "tw/eeprom.h"
#include "messages.h"

#include "eeprom_otp.h"

static void get_address_and_size(eeprom_data_type_t type, uint32_t *address, 
                                 uint32_t *size);

/**
 * @brief Function to read from the car's EEPROM.
 * 
 * @param type Type of data to read.
 * @param buffer Buffer to hold the data read. This buffer should be large 
 * enough to hold the data being read, and should already be allocated by the
 * caller.
 * @param buf_size Size of the buffer.
 * @return int The size of the data that was read, in bytes.
 */
int eeprom_read(eeprom_data_type_t type, uint32_t *buffer, size_t buf_size)
{
    uint32_t address = 0;
    uint32_t read_size = 0;
    get_address_and_size(type, &address, &read_size);
    if (read_size > buf_size)
    {
        
        while(1);
    }

    EEPROMRead(buffer, address, read_size);

    switch(type)
    {
        case EDT_CAR_ID:
        {
            xor_eeprom_car_id((uint8_t *)buffer);
            break;
        }
        case EDT_NONCE_SEED:
        {
            xor_eeprom_nonce_seed((uint8_t *)buffer);
            break;
        }
        case EDT_CAR_E_PRIVATE_KEY:
        {
            xor_eeprom_car_encryption_private_key((uint8_t *)buffer);
            break;
        }
        case EDT_CAR_S_PRIVATE_KEY:
        {
            xor_eeprom_car_signature_private_key((uint8_t *)buffer);
            break;
        }
        case EDT_PF_E_PUBLIC_KEY:
        {
            xor_eeprom_paired_fob_encryption_public_key((uint8_t *)buffer);
            break;
        }
        case EDT_PF_S_PUBLIC_KEY:
        {
            xor_eeprom_paired_fob_signature_public_key((uint8_t *)buffer);
            break;
        }
        case EDT_DEPLOYMENT_S_PUBLIC_KEY:
        {
            xor_eeprom_deployment_signature_public_key((uint8_t *)buffer);
            break;
        }
        case EDT_FEATURE_MESSAGE_1:
        {
            break;
        }
        case EDT_FEATURE_MESSAGE_2:
        {
            break;
        }
        case EDT_FEATURE_MESSAGE_3:
        {
            break;
        }
        case EDT_UNLOCK_MESSAGE:
        {
            break;
        }
        default:
        {
            
            while(1);
        }
    }

    return read_size;
}

/**
 * @brief Function to write to the car's EEPROM.
 * 
 * @param type Type of data to write.
 * @param buffer Buffer which contains the data to be written. The size of this
 * buffer should be appropriate for the type of data being written.
 * @param buf_size Size of the buffer.
 * @return int The size of the data that was written, in bytes.
 */
int eeprom_write(eeprom_data_type_t type, uint32_t *buffer, size_t buf_size)
{
    uint32_t address = 0;
    uint32_t write_size = 0;
    get_address_and_size(type, &address, &write_size);
    if (write_size > buf_size)
    {
        // Buffer does not contain sufficient data
        while(1);
    }

    EEPROMProgram(buffer, address, write_size);

    return write_size;
}


/**
 * @brief Get the address and size of a specific type of EEPROM data.
 * 
 * @param type Type of the data.
 * @param address Variable to hold the address.
 * @param size Variable to hold the size.
 */
static void get_address_and_size(eeprom_data_type_t type, uint32_t *address, 
                                 uint32_t *size)
{
    switch(type)
    {
        case EDT_CAR_ID:
        {
            *size = sizeof(uint32_t);
            *address = EEPROM_CAR_ID;
            break;
        }
        case EDT_NONCE_SEED:
        {
            *size = sizeof(uint32_t);
            *address = EEPROM_NONCE_SEED;
            break;
        }
        case EDT_CAR_E_PRIVATE_KEY:
        {
            *size = PRIVATE_KEY_LEN;
            *address = EEPROM_CAR_ENCRYPTION_PRIVATE_KEY;
            break;
        }
        case EDT_CAR_S_PRIVATE_KEY:
        {
            *size = PRIVATE_KEY_LEN;
            *address = EEPROM_CAR_SIGNATURE_PRIVATE_KEY;
            break;
        }
        case EDT_PF_E_PUBLIC_KEY:
        {
            *size = PUBLIC_KEY_LEN;
            *address = EEPROM_PAIRED_FOB_ENCRYPTION_PUBLIC_KEY;
            break;
        }
        case EDT_PF_S_PUBLIC_KEY:
        {
            *size = PUBLIC_KEY_LEN;
            *address = EEPROM_PAIRED_FOB_SIGNATURE_PUBLIC_KEY;
            break;
        }
        case EDT_DEPLOYMENT_S_PUBLIC_KEY:
        {
            *size = PUBLIC_KEY_LEN;
            *address = EEPROM_DEPLOYMENT_SIGNATURE_PUBLIC_KEY;
            break;
        }
        case EDT_RNG_SEED:
        {
            *size = HASH_LEN;
            *address = EEPROM_RNG_SEED;
        }
        case EDT_FEATURE_MESSAGE_1:
        {
            *size = FEATURE_MSG_LEN;
            *address = EEPROM_FEATURE_1_MESSAGE;
            break;
        }
        case EDT_FEATURE_MESSAGE_2:
        {
            *size = FEATURE_MSG_LEN;
            *address = EEPROM_FEATURE_2_MESSAGE;
            break;
        }
        case EDT_FEATURE_MESSAGE_3:
        {
            *size = FEATURE_MSG_LEN;
            *address = EEPROM_FEATURE_3_MESSAGE;
            break;
        }
        case EDT_UNLOCK_MESSAGE:
        {
            *size = UNLOCK_MSG_LEN;
            *address = EEPROM_UNLOCK_MESSAGE;
            break;
        }
        default:
        {
            
            while(1);
        }
    }
}
