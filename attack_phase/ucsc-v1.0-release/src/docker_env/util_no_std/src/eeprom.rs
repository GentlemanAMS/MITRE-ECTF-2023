//! This module contains an interface to read from and write to the EEPROM.

use cortex_m::asm::delay;
use tm4c123x_hal::sysctl::{self, Domain, PowerControl, PowerState, RunMode};
use tm4c123x_hal::tm4c123x::EEPROM;
use ucsc_ectf_eeprom_layout::EepromFieldBounds;

pub use ucsc_ectf_eeprom_layout::EepromReadField;
pub use ucsc_ectf_eeprom_layout::EepromReadOnlyField;
pub use ucsc_ectf_eeprom_layout::EepromReadWriteField;
pub use ucsc_ectf_eeprom_layout::{
    BYTE_FIELD_SIZE, CAR_ID_SIZE, MESSAGE_SIZE, PACKAGED_FEATURE_SIGNED_SIZE, PAIRING_PIN_SIZE,
    PUBLIC_KEY_SIZE, SECRET_SIZE, SIGNATURE_SIZE,
};

/// The EEPROM controller. Holds a mutable reference to the EEPROM peripheral.
pub struct EepromController<'a> {
    /// The EEPROM peripheral.
    eeprom: &'a mut EEPROM,
    /// Power control.
    power_control: &'a PowerControl,
}

/// An enum for errors that can occur when reading from or writing to the EEPROM.
#[derive(Debug)]
pub enum EepromError {
    /// An error for when the EEPROM controller fails to initialize.
    InitError,
    /// An error for when the supplied buffer is too small to hold the EEPROM field data.
    SizeError,
    /// An error for when a write is performed without permission.
    WritePermissionError,
}

impl<'a> EepromController<'a> {
    /// The number of bytes in a word.
    const BYTES_PER_WORD: usize = 4;

    /// The number of words in a block.
    const WORDS_PER_BLOCK: usize = 16;

    /// Creates a new EEPROM controller.
    ///
    /// Errors:
    /// - [EepromError::InitError] if the EEPROM controller fails to initialize.
    pub(crate) fn new(
        eeprom: &'a mut EEPROM,
        power_control: &'a PowerControl,
    ) -> Result<Self, EepromError> {
        // Create the EEPROM controller.
        let controller = EepromController {
            eeprom,
            power_control,
        };

        // Enable the EEPROM peripheral by setting the RCGCEEPROM register.
        sysctl::control_power(power_control, Domain::Eeprom, RunMode::Run, PowerState::On);

        // Add 3 cycles onto power control NOPs to total to a 6 cycle delay. See page 539 of the
        // datasheet.
        delay(3);

        // Wait for the EEPROM to be ready.
        controller.wait_for_done();

        // Reset the EEPROM.
        sysctl::reset(power_control, Domain::Eeprom);

        // Wait 6 cycles. See page 539 of the datasheet.
        delay(6);

        // Wait for the EEPROM to be ready.
        controller.wait_for_done();

        // Check EESUPP for errors.
        let eesupp = controller.eeprom.eesupp.read();

        if eesupp.pretry().bit_is_set() || eesupp.eretry().bit_is_set() {
            return Err(EepromError::InitError);
        }

        Ok(controller)
    }

    /// Spins while the EEPROM is working.
    fn wait_for_done(&self) {
        while self.eeprom.eedone.read().working().bit_is_set() {}
    }

    /// Checks that the field is within the EEPROM and that the address is word-aligned. Returns the
    /// word count.
    fn checked_get_word_count(&self, field_bounds: &EepromFieldBounds) -> usize {
        // Check that the address is word-aligned.
        debug_assert!((field_bounds.address % Self::BYTES_PER_WORD) == 0);

        // Check that the field is within the EEPROM.
        let end_address = field_bounds.address + field_bounds.size - 1;
        let eeprom_size = self.eeprom.eesize.read().wordcnt().bits();
        debug_assert!((end_address / Self::BYTES_PER_WORD) < eeprom_size.into());

        // Find word count.
        let mut word_count = field_bounds.size / Self::BYTES_PER_WORD;

        // Field size is not a multiple of a word size.
        if (field_bounds.size % Self::BYTES_PER_WORD) != 0 {
            word_count += 1;
        }

        word_count
    }

    /// Sets the EEPROM block and offset to the given byte address.
    fn set_address(&mut self, address: usize) {
        // SAFETY: Writing to this register is safe because it is data-race free. This guarantee
        // comes from the fact that the EEPROM is borrowed mutably.
        self.eeprom.eeblock.write(|w| unsafe {
            w.block()
                .bits((address / Self::BYTES_PER_WORD / Self::WORDS_PER_BLOCK) as u16)
        });

        // SAFETY: Writing to this register is safe because it is data-race free. This guarantee
        // comes from the fact that the EEPROM is borrowed mutably.
        self.eeprom.eeoffset.write(|w| unsafe {
            w.offset()
                .bits(((address / Self::BYTES_PER_WORD) % Self::WORDS_PER_BLOCK) as u8)
        });
    }

    /// Reads a slice of bytes from the EEPROM. Returns the number of bytes read.
    ///
    /// # Errors:
    /// - [EepromError::SizeError] if the destination buffer is too small to hold the EEPROM field.
    pub fn read_slice<T: EepromReadField>(
        &mut self,
        field: T,
        dest: &mut [u8],
    ) -> Result<usize, EepromError> {
        // Check that the destination buffer is large enough.
        let field_bounds = field.get_field_bounds();

        if dest.len() < field_bounds.size {
            return Err(EepromError::SizeError);
        }

        // Perform sanity checks and get word count.
        let word_count = self.checked_get_word_count(&field_bounds);

        // Read from the EEPROM.
        self.set_address(field_bounds.address);

        for i in 0..word_count {
            // Read the word and increment offset.
            let word = self.eeprom.eerdwrinc.read().bits().to_le_bytes();

            // On last word and the field size is not a multiple of a word size.
            if (i == (word_count - 1)) && ((field_bounds.size % Self::BYTES_PER_WORD) != 0) {
                // Copy the partial word to the destination buffer.
                dest[i * Self::BYTES_PER_WORD..field_bounds.size]
                    .copy_from_slice(&word[..(field_bounds.size % Self::BYTES_PER_WORD)]);
            } else {
                // Copy the full word to the destination buffer.
                dest[(i * Self::BYTES_PER_WORD)..((i + 1) * Self::BYTES_PER_WORD)]
                    .copy_from_slice(&word);
            }

            // Increment block for last word in block when not on the last word to read.
            if (i != (word_count - 1)) && (self.eeprom.eeoffset.read().offset().bits() == 0) {
                // SAFETY: Writing to this register is safe because it is data-race free. This
                // guarantee comes from the fact that the EEPROM is borrowed mutably.
                self.eeprom
                    .eeblock
                    .modify(|r, w| unsafe { w.block().bits(r.block().bits() + 1) });
            }
        }

        Ok(field_bounds.size)
    }

    /// Writes a slice of bytes to the EEPROM.
    ///
    /// # Errors:
    /// - [EepromError::SizeError] if the source buffer is not the size of the EEPROM field.
    pub fn write_slice(
        &mut self,
        field: EepromReadWriteField,
        src: &[u8],
    ) -> Result<(), EepromError> {
        // Check that the source buffer is the correct size.
        let field_bounds = field.get_field_bounds();

        if src.len() != field_bounds.size {
            return Err(EepromError::SizeError);
        }

        // Perform sanity checks and get word count.
        let word_count = self.checked_get_word_count(&field_bounds);

        // Write to the EEPROM.
        self.wait_for_done();
        self.set_address(field_bounds.address);

        for i in 0..word_count {
            // On last word and the field size is not a multiple of a word size.
            if (i == (word_count - 1)) && ((field_bounds.size % Self::BYTES_PER_WORD) != 0) {
                // Grab existing word without incrementing offset.
                let existing_word = self.eeprom.eerdwr.read().bits().to_le_bytes();

                // Copy the partial word to the write register.
                self.eeprom.eerdwrinc.write(|w| {
                    let mut word_le_bytes = [0; Self::BYTES_PER_WORD];
                    let bytes_left = field_bounds.size % Self::BYTES_PER_WORD;

                    // Copy bytes from the source buffer.
                    word_le_bytes[..bytes_left]
                        .copy_from_slice(&src[i * Self::BYTES_PER_WORD..field_bounds.size]);

                    // Copy bytes from the existing word.
                    word_le_bytes[bytes_left..].copy_from_slice(&existing_word[bytes_left..]);

                    // SAFETY: Writing to this register is safe because it is data-race free. This
                    // guarantee comes from the fact that the EEPROM is borrowed mutably.
                    unsafe { w.bits(u32::from_le_bytes(word_le_bytes)) }
                });
            } else {
                // Copy the full word to the write register.
                // SAFETY: Writing to this register is safe because it is data-race free. This
                // guarantee comes from the fact that the EEPROM is borrowed mutably.
                self.eeprom.eerdwrinc.write(|w| unsafe {
                    w.bits(u32::from_le_bytes(
                        src[(i * Self::BYTES_PER_WORD)..((i + 1) * Self::BYTES_PER_WORD)]
                            .try_into()
                            .unwrap(),
                    ))
                });
            }

            // Wait 10 cycles. Add delay before checking if done to allow time to update.
            delay(10);

            // Wait for the EEPROM to be done writing.
            self.wait_for_done();

            // Check for no write permission.
            if self.eeprom.eedone.read().noperm().bit_is_set() {
                return Err(EepromError::WritePermissionError);
            }

            // Increment block for last word in block when not on the last word to read.
            if (i != (word_count - 1)) && (self.eeprom.eeoffset.read().offset().bits() == 0) {
                // SAFETY: Writing to this register is safe because it is data-race free. This
                // guarantee comes from the fact that the EEPROM is borrowed mutably.
                self.eeprom
                    .eeblock
                    .modify(|r, w| unsafe { w.block().bits(r.block().bits() + 1) });
            }
        }

        Ok(())
    }

    /// Dumps the contents of the EEPROM. Destination buffer should be large enough to hold the entire
    /// EEPROM.
    ///
    /// # Errors:
    /// - [EepromError::SizeError] if the destination buffer is too small to hold the EEPROM.
    #[cfg(debug_assertions)]
    pub fn dump_mem(&mut self, dest: &mut [u8]) -> Result<(), EepromError> {
        let word_count: usize = self.eeprom.eesize.read().wordcnt().bits().into();
        let eeprom_size = word_count * Self::BYTES_PER_WORD;

        if dest.len() < eeprom_size {
            return Err(EepromError::SizeError);
        }

        // Read from the EEPROM.
        self.set_address(0);

        for i in 0..word_count {
            // Read the word and increment offset.
            let word = self.eeprom.eerdwrinc.read().bits().to_le_bytes();

            // Copy the full word to the destination buffer.
            dest[(i * Self::BYTES_PER_WORD)..((i + 1) * Self::BYTES_PER_WORD)]
                .copy_from_slice(&word);

            // Increment block for last word in block when not on the last word to read.
            if (i != (word_count - 1)) && (self.eeprom.eeoffset.read().offset().bits() == 0) {
                // SAFETY: Writing to this register is safe because it is data-race free. This
                // guarantee comes from the fact that the EEPROM is borrowed mutably.
                self.eeprom
                    .eeblock
                    .modify(|r, w| unsafe { w.block().bits(r.block().bits() + 1) });
            }
        }

        Ok(())
    }

    /// Erases the entire EEPROM.
    #[cfg(debug_assertions)]
    pub fn erase_mem(&mut self) {
        // Start mass erase.
        const ERASE_KEY: u16 = 0xE37B;

        self.eeprom
            .eedbgme
            .write(|w| unsafe { w.key().bits(ERASE_KEY).me().set_bit() });

        // Wait for done.
        while self.eeprom.eedone.read().working().bit_is_set() {}

        // Reset peripheral.
        sysctl::reset(self.power_control, Domain::Eeprom);

        // Wait 6 cycles. See page 539 of the datasheet.
        delay(6);

        // Wait for done.
        while self.eeprom.eedone.read().working().bit_is_set() {}
    }
}

impl<'a> Drop for EepromController<'a> {
    fn drop(&mut self) {
        // Disable the EEPROM.
        sysctl::control_power(
            self.power_control,
            Domain::Eeprom,
            RunMode::Run,
            PowerState::Off,
        );
    }
}
