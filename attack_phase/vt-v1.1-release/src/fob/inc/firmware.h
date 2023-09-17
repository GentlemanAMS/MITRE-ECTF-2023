#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "inc/hw_ints.h"
#include "inc/hw_memmap.h"

#include "driverlib/eeprom.h"
#include "driverlib/flash.h"
#include "driverlib/gpio.h"
#include "driverlib/interrupt.h"
#include "driverlib/pin_map.h"
#include "driverlib/sysctl.h"
#include "driverlib/timer.h"

#include "secrets.h"
#include "public_key.h"

#include "board_link.h"
#include "feature_list.h"
#include "uart.h"
#include "aes.h"

#include "uECC.h"
#include "sha2.h"
#include "curve-specific.inc"

#define FOB_STATE_PTR 0x3FC00
#define FOB_DATA_SIZE         \
  (sizeof(FOB_DATA) % 4 == 0) \
      ? sizeof(FOB_DATA)      \
      : sizeof(FOB_DATA) + (4 - (sizeof(FOB_DATA) % 4))
#define FLASH_PAIRED 0x00
#define FLASH_UNPAIRED 0xFF

typedef enum {
  CAR_PASSWORD,
  FOB_PASSWORD
}key_type;

/*** Structure definitions ***/
// Defines a struct for the format of an enable message
typedef struct
{
  uint8_t car_id[8];
  uint8_t feature;
  uint8_t signature[128];
} ENABLE_PACKET;

// Defines a struct for the format of a pairing message
typedef struct
{
  uint8_t car_id[8];
  uint8_t password[16];
  uint8_t pin_hash[64];
} PAIR_PACKET;

// Defines a struct for the format of start message
typedef struct
{
  uint8_t car_id[8];
  uint8_t num_active;
  uint8_t features[NUM_FEATURES];
} FEATURE_DATA;

// Defines a struct for storing the state in flash
typedef struct
{
  uint8_t paired;
  PAIR_PACKET pair_info;
  FEATURE_DATA feature_info;
} FOB_DATA;

/*** Function definitions ***/

// Core functions - all functionality supported by fob
void pairFob(FOB_DATA *fob_state_ram);
void unlockCar(FOB_DATA *fob_state_ram);
void enableFeature(FOB_DATA *fob_state_ram);
void startCar(FOB_DATA *fob_state_ram);

// Helper functions - receive ack message
uint8_t receiveAck();
static uint8_t* read_key(key_type key_name,  FOB_DATA* fob_state_ram);
static void encrypt(uint8_t* plaintext, key_type key_name, FOB_DATA* fob_state_ram);
static void decrypt(uint8_t* ciphertext, key_type key_name,  FOB_DATA* fob_state_ram);
static void getRandomNumber(uint8_t dest[] , uint8_t bytes_length);
void timer_set_start(void);

//static bool debug_print(const char *text);
