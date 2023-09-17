// Addresses of data in car EEPROM

#ifndef __EEPROM_
#define __EEPROM_

#include <stdint.h>

#define EEPROM_CAR_ID       (0x40) // 4 bytes
#define EEPROM_NONCE_SEED   (0x44) // 4 bytes

#define EEPROM_CAR_ENCRYPTION_PRIVATE_KEY   (0x80) // 32 bytes
#define EEPROM_CAR_SIGNATURE_PRIVATE_KEY    (0xa0) // 32 bytes

#define EEPROM_PAIRED_FOB_ENCRYPTION_PUBLIC_KEY   (0xc0) // 32 bytes
#define EEPROM_PAIRED_FOB_SIGNATURE_PUBLIC_KEY    (0xe0) // 32 bytes

#define EEPROM_DEPLOYMENT_SIGNATURE_PUBLIC_KEY    (0x100) // 32 bytes

#define EEPROM_RNG_SEED_SIZE    (0x500)
#define EEPROM_RNG_SEED         (0x200)

#define EEPROM_MESSAGE_LEN (0x40)
#define EEPROM_FEATURE_3_MESSAGE  (0x700)   // 64 bytes
#define EEPROM_FEATURE_2_MESSAGE  (0x740)   // 64 bytes
#define EEPROM_FEATURE_1_MESSAGE  (0x780)   // 64 bytes
#define EEPROM_UNLOCK_MESSAGE     (0x7c0)   // 64 bytes

#endif
