//! This crate contains definitions for the EEPROM layout.

#![warn(missing_docs)]
#![no_std]

/// The start address of the EEPROM.
const EEPROM_START_ADDRESS: usize = 0x000;

/// The start address of the EEPROM reserved message space.
const EEPROM_MESSAGES_START_ADDRESS: usize = 0x700;

/// The size of encryption secrets. 256 bits = 32 bytes.
pub const SECRET_SIZE: usize = 32;

/// The size of Postcard-encoded signatures.
pub const SIGNATURE_SIZE: usize = 64;

/// The max size of Postcard-encoded public keys.
pub const PUBLIC_KEY_SIZE: usize = 128;

/// The size of unlock/feature messages.
pub const MESSAGE_SIZE: usize = 64;

/// The size of the car ID. 32 bits = 4 bytes.
pub const CAR_ID_SIZE: usize = 4;

/// The size of a byte. Deal with it.
pub const BYTE_FIELD_SIZE: usize = 4;

/// The size of the pairing PIN.
pub const PAIRING_PIN_SIZE: usize = 4;

/// The size of a signed packaged feature.
pub const PACKAGED_FEATURE_SIGNED_SIZE: usize = 96;

/// The bounds of the paired fob's pairing signing key EEPROM field.
const PAIRED_FOB_PAIRING_SIGNING_KEY_BOUNDS: EepromFieldBounds = EepromFieldBounds {
    address: EEPROM_START_ADDRESS,
    size: SECRET_SIZE,
};

/// The bounds of the paired fob's pairing public key signature EEPROM field.
const PAIRED_FOB_PAIRING_PUBLIC_KEY_SIGNATURE_BOUNDS: EepromFieldBounds = EepromFieldBounds {
    address: PAIRED_FOB_PAIRING_SIGNING_KEY_BOUNDS.address
        + PAIRED_FOB_PAIRING_SIGNING_KEY_BOUNDS.size,
    size: SIGNATURE_SIZE,
};

/// The bounds of the paired fob's manufacturer pairing verifying key EEPROM field.
const PAIRING_MANUFACTURER_PAIRED_FOB_VERIFYING_KEY_BOUNDS: EepromFieldBounds = EepromFieldBounds {
    address: PAIRED_FOB_PAIRING_PUBLIC_KEY_SIGNATURE_BOUNDS.address
        + PAIRED_FOB_PAIRING_PUBLIC_KEY_SIGNATURE_BOUNDS.size,
    size: PUBLIC_KEY_SIZE,
};

/// The bounds of the unpaired fob's manufacturer pairing verifying key EEPROM field.
const PAIRING_MANUFACTURER_UNPAIRED_FOB_VERIFYING_KEY_BOUNDS: EepromFieldBounds =
    EepromFieldBounds {
        address: PAIRING_MANUFACTURER_PAIRED_FOB_VERIFYING_KEY_BOUNDS.address
            + PAIRING_MANUFACTURER_PAIRED_FOB_VERIFYING_KEY_BOUNDS.size,
        size: PUBLIC_KEY_SIZE,
    };

/// The bounds of the feature verifying key EEPROM field.
const FEATURE_VERIFYING_KEY_BOUNDS: EepromFieldBounds = EepromFieldBounds {
    address: PAIRING_MANUFACTURER_UNPAIRED_FOB_VERIFYING_KEY_BOUNDS.address
        + PAIRING_MANUFACTURER_UNPAIRED_FOB_VERIFYING_KEY_BOUNDS.size,
    size: PUBLIC_KEY_SIZE,
};

/// The bounds of the secret seed EEPROM field.
const SECRET_SEED_BOUNDS: EepromFieldBounds = EepromFieldBounds {
    address: FEATURE_VERIFYING_KEY_BOUNDS.address + FEATURE_VERIFYING_KEY_BOUNDS.size,
    size: SECRET_SIZE,
};

/// The bounds of the unpaired fob's pairing signing key EEPROM field.
const UNPAIRED_FOB_PAIRING_SIGNING_KEY_BOUNDS: EepromFieldBounds = EepromFieldBounds {
    address: SECRET_SEED_BOUNDS.address + SECRET_SEED_BOUNDS.size,
    size: SECRET_SIZE,
};

/// The bounds of the unpaired fob's pairing public key signature EEPROM field.
const UNPAIRED_FOB_PAIRING_PUBLIC_KEY_SIGNATURE_BOUNDS: EepromFieldBounds = EepromFieldBounds {
    address: UNPAIRED_FOB_PAIRING_SIGNING_KEY_BOUNDS.address
        + UNPAIRED_FOB_PAIRING_SIGNING_KEY_BOUNDS.size,
    size: SIGNATURE_SIZE,
};

/// The bounds of the key fob encryption key (unlock key 1) EEPROM field.
const KEY_FOB_ENCRYPTION_KEY_BOUNDS: EepromFieldBounds = EepromFieldBounds {
    address: UNPAIRED_FOB_PAIRING_PUBLIC_KEY_SIGNATURE_BOUNDS.address
        + UNPAIRED_FOB_PAIRING_PUBLIC_KEY_SIGNATURE_BOUNDS.size,
    size: SECRET_SIZE,
};

/// The bounds of the car encryption key (unlock key 2) EEPROM field.
const CAR_ENCRYPTION_KEY_BOUNDS: EepromFieldBounds = EepromFieldBounds {
    address: KEY_FOB_ENCRYPTION_KEY_BOUNDS.address + KEY_FOB_ENCRYPTION_KEY_BOUNDS.size,
    size: SECRET_SIZE,
};

/// The bounds of the car ID EEPROM field.
const CAR_ID_BOUNDS: EepromFieldBounds = EepromFieldBounds {
    address: CAR_ENCRYPTION_KEY_BOUNDS.address + CAR_ENCRYPTION_KEY_BOUNDS.size,
    size: CAR_ID_SIZE,
};

/// The bounds of the pairing byte EEPROM field.
const PAIRING_BYTE_BOUNDS: EepromFieldBounds = EepromFieldBounds {
    address: CAR_ID_BOUNDS.address + CAR_ID_BOUNDS.size,
    size: BYTE_FIELD_SIZE,
};

/// The bounds of the pairing PIN EEPROM field.
const PAIRING_PIN_BOUNDS: EepromFieldBounds = EepromFieldBounds {
    address: PAIRING_BYTE_BOUNDS.address + PAIRING_BYTE_BOUNDS.size,
    size: PAIRING_PIN_SIZE,
};

/// The bounds of the pairing longer cooldown byte EEPROM field.
const PAIRING_LONGER_COOLDOWN_BYTE_BOUNDS: EepromFieldBounds = EepromFieldBounds {
    address: PAIRING_PIN_BOUNDS.address + PAIRING_PIN_BOUNDS.size,
    size: BYTE_FIELD_SIZE,
};

/// The bounds of the feature one signed packaged feature EEPROM field.
const FEATURE_ONE_SIGNED_PACKAGED_BOUNDS: EepromFieldBounds = EepromFieldBounds {
    address: PAIRING_LONGER_COOLDOWN_BYTE_BOUNDS.address + PAIRING_LONGER_COOLDOWN_BYTE_BOUNDS.size,
    size: PACKAGED_FEATURE_SIGNED_SIZE,
};

/// The bounds of the feature two signed packaged feature EEPROM field.
const FEATURE_TWO_SIGNED_PACKAGED_BOUNDS: EepromFieldBounds = EepromFieldBounds {
    address: FEATURE_ONE_SIGNED_PACKAGED_BOUNDS.address + FEATURE_ONE_SIGNED_PACKAGED_BOUNDS.size,
    size: PACKAGED_FEATURE_SIGNED_SIZE,
};

/// The bounds of the feature three signed packaged feature EEPROM field.
const FEATURE_THREE_SIGNED_PACKAGED_BOUNDS: EepromFieldBounds = EepromFieldBounds {
    address: FEATURE_TWO_SIGNED_PACKAGED_BOUNDS.address + FEATURE_TWO_SIGNED_PACKAGED_BOUNDS.size,
    size: PACKAGED_FEATURE_SIGNED_SIZE,
};

/// The bounds of the feature three message EEPROM field.
const FEATURE_THREE_MESSAGE_BOUNDS: EepromFieldBounds = EepromFieldBounds {
    address: EEPROM_MESSAGES_START_ADDRESS,
    size: MESSAGE_SIZE,
};

/// The bounds of the feature two message EEPROM field.
const FEATURE_TWO_MESSAGE_BOUNDS: EepromFieldBounds = EepromFieldBounds {
    address: FEATURE_THREE_MESSAGE_BOUNDS.address + FEATURE_THREE_MESSAGE_BOUNDS.size,
    size: MESSAGE_SIZE,
};

/// The bounds of the feature one message EEPROM field.
const FEATURE_ONE_MESSAGE_BOUNDS: EepromFieldBounds = EepromFieldBounds {
    address: FEATURE_TWO_MESSAGE_BOUNDS.address + FEATURE_TWO_MESSAGE_BOUNDS.size,
    size: MESSAGE_SIZE,
};

/// The bounds of the unlock message EEPROM field.
const UNLOCK_MESSAGE_BOUNDS: EepromFieldBounds = EepromFieldBounds {
    address: FEATURE_ONE_MESSAGE_BOUNDS.address + FEATURE_ONE_MESSAGE_BOUNDS.size,
    size: MESSAGE_SIZE,
};

/// This enum specifies the fields of the EEPROM that can be read from, but not written to.
#[derive(Copy, Clone)]
pub enum EepromReadOnlyField {
    /// The secret of the key used for the key-signing key in the Diffie-Hellman key exchange during pairing as a paired fob.
    PairedFobPairingSigningKey,
    /// The signature of the SEC1 public key-signing key used for the Diffie-Hellman key exchange during pairing as a paired fob.
    PairedFobPairingPublicKeySignature,
    /// The DER-encoded verifying key used for verifying a paired fob's key-signing key during the Diffie-Hellman key exchange while pairing.
    PairingManufacturerPairedFobVerifyingKey,
    /// The DER-encoded verifying key used for verifying an unpaired fob's key-signing key during the Diffie-Hellman key exchange while pairing.
    PairingManufacturerUnpairedFobVerifyingKey,
    /// The DER-encoded verifying key used to verify packaged features.
    FeatureVerifyingKey,
    /// The key used as a starting point for the RNG seed hash.
    SecretSeed,
    /// The message to be printed when feature three is enabled.
    FeatureThreeMessage,
    /// The message to be printed when feature two is enabled.
    FeatureTwoMessage,
    /// The message to be printed when feature one is enabled.
    FeatureOneMessage,
    /// The message to be printed when the car is successfully unlocked.
    UnlockMessage,
}

/// This enum specifies the fields of the EEPROM that can be read from and written to.
#[derive(Copy, Clone)]
pub enum EepromReadWriteField {
    /// The secret of the key used for the key-signing key in the Diffie-Hellman key exchange during pairing as an unpaired fob.
    UnpairedFobPairingSigningKey,
    /// The signature of the SEC1 public key-signing key used for the Diffie-Hellman key exchange during pairing as an unpaired fob.
    UnpairedFobPairingPublicKeySignature,
    /// The key used to facilitate encrypted communications from a paired key fob to a car during the
    /// unlock sequence.
    KeyFobEncryptionKey,
    /// The key used to facilitate encrypted communications from a car to a paired key fob during the
    /// unlock sequence.
    CarEncryptionKey,
    /// The car ID.
    CarId,
    /// Whether or not a key fob is paired with a car.
    PairingByte,
    /// The pairing PIN used to authenticate the pairing of an unpaired key fob to a car, given a
    /// paired key fob.
    PairingPin,
    /// Whether or not the longer pairing cooldown is active.
    PairingLongerCooldownByte,
    /// The signed packaged feature for feature one.
    FeatureOneSignedPackaged,
    /// The signed packaged feature for feature two.
    FeatureTwoSignedPackaged,
    /// The signed packaged feature for feature three.
    FeatureThreeSignedPackaged,
}

/// A struct for EEPROM field bounds.
pub struct EepromFieldBounds {
    /// The address of the EEPROM field.
    pub address: usize,
    /// The size of the EEPROM field.
    pub size: usize,
}

/// A trait for all readable EEPROM fields.
pub trait EepromReadField: Copy {
    /// Returns the bounds of the EEPROM field.
    fn get_field_bounds(&self) -> EepromFieldBounds;
}

impl EepromReadField for EepromReadOnlyField {
    fn get_field_bounds(&self) -> EepromFieldBounds {
        match self {
            Self::PairedFobPairingSigningKey => PAIRED_FOB_PAIRING_SIGNING_KEY_BOUNDS,
            Self::PairedFobPairingPublicKeySignature => {
                PAIRED_FOB_PAIRING_PUBLIC_KEY_SIGNATURE_BOUNDS
            }
            Self::PairingManufacturerPairedFobVerifyingKey => {
                PAIRING_MANUFACTURER_PAIRED_FOB_VERIFYING_KEY_BOUNDS
            }
            Self::PairingManufacturerUnpairedFobVerifyingKey => {
                PAIRING_MANUFACTURER_UNPAIRED_FOB_VERIFYING_KEY_BOUNDS
            }
            Self::FeatureVerifyingKey => FEATURE_VERIFYING_KEY_BOUNDS,
            Self::SecretSeed => SECRET_SEED_BOUNDS,
            Self::FeatureThreeMessage => FEATURE_THREE_MESSAGE_BOUNDS,
            Self::FeatureTwoMessage => FEATURE_TWO_MESSAGE_BOUNDS,
            Self::FeatureOneMessage => FEATURE_ONE_MESSAGE_BOUNDS,
            Self::UnlockMessage => UNLOCK_MESSAGE_BOUNDS,
        }
    }
}

impl EepromReadField for EepromReadWriteField {
    fn get_field_bounds(&self) -> EepromFieldBounds {
        match self {
            Self::UnpairedFobPairingSigningKey => UNPAIRED_FOB_PAIRING_SIGNING_KEY_BOUNDS,
            Self::UnpairedFobPairingPublicKeySignature => {
                UNPAIRED_FOB_PAIRING_PUBLIC_KEY_SIGNATURE_BOUNDS
            }
            Self::KeyFobEncryptionKey => KEY_FOB_ENCRYPTION_KEY_BOUNDS,
            Self::CarEncryptionKey => CAR_ENCRYPTION_KEY_BOUNDS,
            Self::CarId => CAR_ID_BOUNDS,
            Self::PairingByte => PAIRING_BYTE_BOUNDS,
            Self::PairingPin => PAIRING_PIN_BOUNDS,
            Self::PairingLongerCooldownByte => PAIRING_LONGER_COOLDOWN_BYTE_BOUNDS,
            Self::FeatureOneSignedPackaged => FEATURE_ONE_SIGNED_PACKAGED_BOUNDS,
            Self::FeatureTwoSignedPackaged => FEATURE_TWO_SIGNED_PACKAGED_BOUNDS,
            Self::FeatureThreeSignedPackaged => FEATURE_THREE_SIGNED_PACKAGED_BOUNDS,
        }
    }
}
