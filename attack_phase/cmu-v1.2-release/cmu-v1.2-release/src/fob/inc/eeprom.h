// Addresses of data in fobs EEPROM

#ifndef __EEPROM_
#define __EEPROM_

#define EEPROM_IS_PAIRED_FOB    (0x40) // 1 byte, commmon for UPF and PF
#define EEPROM_CAR_ID           (0x44) // 4 bytes
#define EEPROM_FEATURE_BITVEC   (0x48) // 1 byte

// UPF encryption private key, only use in UPF
#define EEPROM_UNPAIRED_FOB_ENCRYPTION_PRIVATE_KEY   (0x80) // 32 bytes

// PF layout below
#define EEPROM_PAIRED_FOB_ENCRYPTION_PRIVATE_KEY   (0x80) // 32 bytes
#define EEPROM_PAIRED_FOB_SIGNATURE_PRIVATE_KEY    (0xa0) // 32 bytes

#define EEPROM_CAR_ENCRYPTION_PUBLIC_KEY   (0xc0) // 32 bytes
#define EEPROM_CAR_SIGNATURE_PUBLIC_KEY    (0xe0) // 32 bytes

#define EEPROM_DEPLOYMENT_SIGNATURE_PUBLIC_KEY       (0x100) // 32 bytes
#define EEPROM_UNPAIRED_FOB_ENCRYPTION_PUBLIC_KEY    (0x120) // 32 bytes

#define EEPROM_CAR_PIN_HASH (0x140) // 64 bytes

#define EEPROM_CAR_PIN_HASH_KEY (0x180) // 64 bytes

#define EEPROM_RNG_SEED_SIZE    (0x500)
#define EEPROM_RNG_SEED         (0x200)

#endif
