
#ifndef __EEPROM_ACCESS_H_
#define __EEPROM_ACCESS_H_

#include <stdint.h>
#include <stddef.h>

/* @brief ENUM to select the type of data to be accessed on a car EEPROM */
typedef enum
{
    EDT_CAR_ID = 0,
    EDT_NONCE_SEED,
    EDT_CAR_E_PRIVATE_KEY,
    EDT_CAR_S_PRIVATE_KEY,
    EDT_PF_E_PUBLIC_KEY,
    EDT_PF_S_PUBLIC_KEY,
    EDT_DEPLOYMENT_S_PUBLIC_KEY,
    EDT_RNG_SEED,
    EDT_FEATURE_MESSAGE_1,
    EDT_FEATURE_MESSAGE_2,
    EDT_FEATURE_MESSAGE_3,
    EDT_UNLOCK_MESSAGE
} eeprom_data_type_t;

int eeprom_read(eeprom_data_type_t type, uint32_t *buffer, size_t buf_size);
int eeprom_write(eeprom_data_type_t type, uint32_t *buffer, size_t buf_size);

#endif /* __EEPROM_ACCESS_H_ */
