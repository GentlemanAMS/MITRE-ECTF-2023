void paired_fob_main();
void paired_fob_pair();
void unpaired_fob_pair();
void unpaired_fob_main();
bool paired_fob_verify_pin();
void halt_and_catch_fire();

#define FOB_STATE_PTR 0x3FC00
#define FLASH_DATA_SIZE         \
  (sizeof(FLASH_DATA) % 4 == 0) \
      ? sizeof(FLASH_DATA)      \
      : sizeof(FLASH_DATA) + (4 - (sizeof(FLASH_DATA) % 4))
#define FLASH_PAIRED 0x00
#define FLASH_UNPAIRED 0xFF