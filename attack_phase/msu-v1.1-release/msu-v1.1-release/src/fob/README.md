# Spartans Secure Key Fob Device Firmware

## Functionality
The secure key fob device will perform a startup routine when powered on, then will
wait in a loop for commands to come either from the Host UART connection or from
the SW1 Button on the board.

When a button press is registered, the secure key fob device will perform an unlock attempt
on the car device connected over the Board UART. It will receive and sign the challenge
issued by the car device, and will send back this response along with the currently held
feature packages.

When a host command is registered, the secure key fob device will perform the requested operation
if it is deemed appropriate. An unpaired fob will follow commands to become paired, while a paired
fob will follow commands to pair an unpaired fob or to enable a feature.

Enabling a feature entails receiving the feature package from the host.

Becoming paired entails receiving and storing the necessary information from an already paired fob.

For a paired fob to pair an unpaired fob entails verifying that the correct pairing PIN is entered
by the host, then sending the necessary information to the connected unpaired fob.

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

