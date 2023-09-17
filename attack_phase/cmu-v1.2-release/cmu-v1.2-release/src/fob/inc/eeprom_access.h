#ifndef __EEPROM_ACCESS_H_
#define __EEPROM_ACCESS_H_


#include <stdint.h>
#include <stddef.h>

/* @brief ENUM to select the type of data to be accessed on a fob EEPROM */
typedef enum
{
    EDT_IS_PAIRED_FOB = 0,
    EDT_CAR_ID,
    EDT_FEATURE_BITVEC,
    EDT_PF_E_PRIVATE_KEY,
    EDT_PF_S_PRIVATE_KEY,
    EDT_UPF_E_PUBLIC_KEY,
    EDT_UPF_E_PRIVATE_KEY,
    EDT_CAR_E_PUBLIC_KEY,
    EDT_CAR_S_PUBLIC_KEY,
    EDT_DEPLOYMENT_S_PUBLIC_KEY,
    EDT_CAR_PIN_HASH,
    EDT_CAR_PIN_HASH_KEY,
    EDT_RNG_SEED
} eeprom_data_type_t;

int eeprom_read(eeprom_data_type_t type, uint32_t *buffer, size_t buf_size);
int eeprom_write(eeprom_data_type_t type, uint32_t *buffer, size_t buf_size);

#endif /* __EEPROM_ACCESS_H_ */
