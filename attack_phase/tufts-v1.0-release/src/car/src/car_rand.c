#include <stdbool.h>
#include <stdint.h>

#include "inc/hw_memmap.h"

#include "driverlib/eeprom.h"
#include "driverlib/timer.h"
#include "isaac.h"

#define EEPROM_SEED_ADDR 0x0
#define EEPROM_SEED_BYTES 1024

void seed_rng(void) {
    EEPROMRead(randrsl, EEPROM_SEED_ADDR, EEPROM_SEED_BYTES);
    // Incorporate timing information
    randrsl[RANDSIZ-1] = TimerValueGet(TIMER1_BASE, TIMER_A);
    randrsl[RANDSIZ-2] = TimerValueGet(TIMER0_BASE, TIMER_A);
    randinit(true);

    // Write new seed
    EEPROMProgram(randrsl, EEPROM_SEED_ADDR, EEPROM_SEED_BYTES);
    // Replace now used random data in randrsl
    isaac();
}