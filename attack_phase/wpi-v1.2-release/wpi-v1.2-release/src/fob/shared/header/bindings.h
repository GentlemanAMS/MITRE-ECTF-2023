/* This is the file that Rust Bindgen will look into when generating C bindings for code */

#include <stdint.h>
#include <stdbool.h>

#define PART_TM4C123GH6PM
#include "../lib/tivaware/driverlib/pin_map.h"
#include "../lib/tivaware/driverlib/gpio.h"
#include "../lib/tivaware/driverlib/sysctl.h"
#include "../lib/tivaware/driverlib/eeprom.h"
#include "../lib/tivaware/driverlib/uart.h"
#include "../lib/tivaware/inc/hw_memmap.h"

