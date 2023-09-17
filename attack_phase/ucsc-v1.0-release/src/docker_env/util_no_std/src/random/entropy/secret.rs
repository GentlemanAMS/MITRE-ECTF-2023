use super::EntropySource;
use crate::{eeprom::EepromController, RuntimePeripherals};
use sha3::{digest::Update, Sha3_256};
use ucsc_ectf_eeprom_layout::{EepromReadOnlyField, SECRET_SIZE};
use zeroize::Zeroize;

/// This entropy source is a constant secret value.
///
/// This struct should not be moved to ensure the secret gets zeroed out on drop.
pub(crate) struct Secret<T: EntropySource> {
    next: T,
    secret: [u8; SECRET_SIZE],
}

impl<T: EntropySource> EntropySource for Secret<T> {
    fn init(peripherals: &mut RuntimePeripherals) -> Self {
        let mut secret = [0; SECRET_SIZE];

        {
            let mut eeprom =
                EepromController::new(&mut peripherals.eeprom, &peripherals.power_control).unwrap();
            eeprom
                .read_slice(EepromReadOnlyField::SecretSeed, &mut secret[..])
                .unwrap();
        }

        Secret {
            next: T::init(peripherals),
            secret,
        }
    }

    fn add_to_hasher(&self, hasher: &mut Sha3_256) {
        hasher.update(&self.secret);
        self.next.add_to_hasher(hasher);
    }
}

impl<T: EntropySource> Drop for Secret<T> {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}
