//! Provides utilities for working with cryptographic nonces.
use chacha20poly1305::{aead, XChaCha20Poly1305};

use crate::{hw::eeprom::EEPROMVar, utils::rng::RandomSource};
use super::error::Error;

/// A nonce compatible with the XChaCha20Poly1305 algorithm.
pub type Nonce = aead::Nonce<XChaCha20Poly1305>;

/// A unique identifier for a nonce.
pub struct NonceID(u32);

impl NonceID {
    /// Returns the ID as an unsigned 32-bit integer.
    fn u32(&self) -> u32 {
        self.0
    }

    /// Generates a new ID, consuming the current one.
    fn next(self) -> Self {
        Self(self.0 + 1)
    }
}

impl From<NonceID> for u32 {
    fn from(value: NonceID) -> Self {
        value.u32()
    }
}

impl From<u32> for NonceID {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl PartialEq for NonceID {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

/// A generator of random nonces for cryptographic operations.
pub trait NonceGenerator {
    /// Generates a nonce from a source of random data.
    fn generate_nonce(&mut self, rng: &mut dyn RandomSource) -> Result<Nonce, Error>;
}

/// A nonce generator that generates mostly-random nonces, with an additional incrementing 
/// identifier that is saved in EEPROM.
pub struct IncrementingNonceGenerator {
    nonce: EEPROMVar<NonceID>,
}

impl IncrementingNonceGenerator {
    pub fn new(nonce: EEPROMVar<NonceID>) -> Self {
        Self { nonce }
    }
}

impl NonceGenerator for IncrementingNonceGenerator {
    fn generate_nonce(&mut self, rng: &mut dyn RandomSource) -> Result<Nonce, Error> {
        let current_nonce_id = self.nonce.read();
        let mut nonce_buffer = [0u8; 24];
        nonce_buffer[20..].copy_from_slice(&current_nonce_id.u32().to_le_bytes()[..]);

        self.nonce.write(&current_nonce_id.next());

        rng.get_random_bytes(&mut nonce_buffer[..20]);
        Ok(Nonce::clone_from_slice(&nonce_buffer[..]))
    }
}

#[cfg(test)]
mod tests {
    use core::cell::RefCell;

    use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

    use crate::{
        comms::noncegenerator::{Nonce, NonceID},
        hw::eeprom::{eeprom_scope, EEPROMVar},
        utils::rng::CryptoRNG,
    };

    use super::{IncrementingNonceGenerator, NonceGenerator};

    #[test]
    fn generate_incrementing_nonces() {
        eeprom_scope(|| {
            let mut nonce = EEPROMVar::<NonceID>::new::<0x0>();
            nonce.write(&NonceID::from(0));

            let mut inc_nonce_gen = IncrementingNonceGenerator::new(nonce);
            let mut rng = CryptoRNG::new([0u8; 32]);

            let nonce_0 = inc_nonce_gen.generate_nonce(&mut rng).unwrap();

            dbg!(nonce_0);
            assert_eq!(nonce_0[20..], [0, 0, 0, 0]);

            let nonce_1 = inc_nonce_gen.generate_nonce(&mut rng).unwrap();

            dbg!(nonce_1);
            assert_eq!(nonce_1[20..], [1, 0, 0, 0]);

            let nonce_2 = inc_nonce_gen.generate_nonce(&mut rng).unwrap();

            dbg!(nonce_2);
            assert_eq!(nonce_2[20..], [2, 0, 0, 0]);
        });
    }
}
