# Spartans Secure Car Device Firmware

## Functionality
The secure car device will perform a startup routine when powered on, then will
wait in a loop for a key fob device to begin an unlock attempt.

Upon receiving an unlock attempt, the secure car device will issue a challenge
to the key fob device. It will allow for a prompt response, then validate the response.
If a valid response to the challenge has been provided, and all features requested in the
response are also valid, then the car will successfully unlock and enable the requested features.

## Layout
The firmware is split into the following files, with headers in `inc/` and source code in `src/`:

* `firmware.{c,h}`: Implements the main functionality of the firmware, including `main()`
* `uart.{c,h}`: Implements communications over theUART interface, reading and writing raw bytes.
* `board_link.{c,h}`: Implements higher-level UART communications, with an emphasis on
      board-to-board communications.

## Libraries
We have included the Tivaware driver library for working with the
microcontroller peripherals. You can find Tivaware in `lib/tivaware`.

We have also included the [Sweet B](https://github.com/westerndigitalcorporation/sweet-b)
library for cryptographic signatures and for cryptographically secure random number generation.
You can find Sweet B in `lib/sweet-b`.