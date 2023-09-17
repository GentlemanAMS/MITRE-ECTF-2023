# Fob Firmware :key:
This directory contains the source code for the fob firmware.

## File Structure

### Source

* [firmware.c](src/firmware.c) : Implements the main functionality of the firmware, including `main()`
* board_link.{[c](src/board_link.c), [h](inc/board_link.h)}: Implements a UART interface between the two developent boards
  with packet structures for communications.
* [feature_list.h](inc/feature_list.h): Includes definitions for utilizing the feature list included
  with the build process in EEPROM. This file should not need to be modified.
* wrappers.{[c](src/wrappers.c), [h](inc/wrapper.h)}: Implements wrapper functions for performing cryptographic operations and reading/writing to EEPROM.
* [ustdlib.c](src/ustdlib.c): Implements a subset of the standard C library.

### Libraries

* [lib/tivaware](lib/tivaware/) For working with the microcontroller peripherals we utilize the Tivaware driver library.
* [lib/ascon](lib/ascon) For cryptographic operations we utilize the ASCON hash function and the ASCON authenticated encryption scheme.