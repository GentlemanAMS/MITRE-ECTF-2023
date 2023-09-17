//! Message types for communication between boards.

use core::fmt::Debug;
use chacha20poly1305::{XChaCha20Poly1305, KeyInit, AeadInPlace};
use ed25519_dalek::{PublicKey, Signature};
use crate::security::constant_time;
use crate::utils::static_slicing::{FixedSizeCopy, StaticRangeIndex};

use super::noncegenerator::Nonce;
use super::packet::Key;
use super::error::Error;

/// A message included in a packet.
pub trait Message: Sized + Clone + Debug {
    /// The unique "type tag" for the message.
    const TYPE_ID: u32;

    /// Attempts to deserialize a buffer into a message.
    fn deserialize_from(input: &[u8; 84]) -> Result<Self, Error>;

    /// Attempts to serialize the message into a buffer, consuming the message
    /// in the process.
    fn serialize_to(self, output: &mut [u8; 84]) -> Result<(), Error>;
}

/// A PIN of 6 hexadecimal digits that is used in the pairing process.
#[derive(Debug, Clone, Copy)]
#[repr(align(8))]
pub struct Pin([u8; 6]);

impl Pin {
    /// Constructs a [`Pin`] from an array of 6 bytes.
    /// Fails if any invalid (i.e., non-hexadecimal) characters
    /// are encountered.
    pub fn new(pin: [u8; 6]) -> Result<Self, Error> {
        pin
            .iter()
            .all(|x| b"0123456789ABCDEFabcdef".contains(x))
            .then_some(Self(pin))
            .ok_or(Error::PinError)
    }

    pub fn as_bytes(&self) -> &[u8; 6] {
        &self.0
    }
}

// Constant Time Compare for Pins
impl PartialEq for Pin {
    fn eq(&self, other: &Self) -> bool {
        constant_time::bytes_equal(&self.0, &other.0)
    }
}

/// Message to initiate the pairing process, sent by an unpaired fob.
#[derive(Clone, Debug, PartialEq)]
pub struct PairRequestMessage {
    /// The PIN being used in the pairing process. (It might not be correct!)
    pub pin: Pin,
}

impl Message for PairRequestMessage {
    const TYPE_ID: u32 = 1;

    fn deserialize_from(input: &[u8; 84]) -> Result<Self, Error> {
        Ok(Self {
            pin: Pin::new(input[StaticRangeIndex::<0, 6>])?,
        })
    }

    fn serialize_to(self, output: &mut [u8; 84]) -> Result<(), Error> {
        output[StaticRangeIndex::<0, 6>].copy_from(self.pin.0);
        Ok(())
    }
}

/// Wrapper around [`u32`] for car IDs.
#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub struct CarID(u32);

impl CarID {
    /// Constructs a [`CarID`] from a [`u32`].
    pub fn new(id: u32) -> Self {
        Self(id)
    }

    /// Constructs a [`CarID`] from an array of 4 bytes.
    pub fn new_from_bytes(bytes: [u8; 4]) -> Self {
        Self::new(u32::from_le_bytes(bytes))
    }

    pub fn u32(self) -> u32 {
        self.0
    }
}

impl From<CarID> for u32 {
    fn from(value: CarID) -> Self {
        value.0
    }
}

/// A 32-byte "password" used to unlock a car.
#[derive(Eq, Debug, Clone)]
pub struct Password([u8; 32]);

impl Password {
    /// Constructs a [`Password`] from an array of 32 bytes.
    pub fn new(val: [u8; 32]) -> Self {
        Self(val)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl PartialEq for Password {
    fn eq(&self, other: &Self) -> bool {
        constant_time::bytes_equal(&self.0, &other.0)
    }
}

/// Message to unlock a car, sent by a paired fob.
#[derive(Clone, Debug, PartialEq)]
pub struct UnlockMessage {
    /// The ID of the car that the fob is paired with.
    pub id: CarID,

    /// The car's unlock password. (It might not be correct!)
    pub passwd: Password,
}

impl Message for UnlockMessage {
    const TYPE_ID: u32 = 2;

    fn deserialize_from(input: &[u8; 84]) -> Result<Self, Error> {
        Ok(Self {
            id: (CarID::new_from_bytes(input[StaticRangeIndex::<0, 4>])),
            passwd: Password::new(input[StaticRangeIndex::<4, 32>]),
        })
    }

    fn serialize_to(self, output: &mut [u8; 84]) -> Result<(), Error> {
        output[StaticRangeIndex::<0, 4>].copy_from(self.id.0.to_le_bytes());
        output[StaticRangeIndex::<4, 32>].copy_from(self.passwd.0);
        Ok(())
    }
}

// An 8-bit feature ID.
#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub struct FeatureNumber(u32);

impl FeatureNumber {
    /// Constructs a [`FeatureNumber`] from a byte.
    pub fn new(num: u8) -> Self {
        Self(num as u32)
    }

    /// Returns the feature ID, consuming the [`FeatureNumber`].
    pub fn val(self) -> u8 {
        self.0 as u8
    }
}

/// Feature information payload, included in a [`EnableFeatureMessage`].
#[derive(Clone, Debug, PartialEq)]
pub struct EnableFeaturePayload {
    /// The ID of the car that the feature is associated with.
    pub car_id: CarID,
    
    /// The ID of the feature.
    pub feature_id: FeatureNumber
}

impl EnableFeaturePayload {
    /// Parses and constructs an [`EnableFeaturePayload`] from an array of 16 bytes.
    pub fn from_bytes(input: &[u8; 16]) -> Self {
        Self {
            car_id: CarID::new_from_bytes(input[StaticRangeIndex::<0, 4>]),
            feature_id: FeatureNumber::new(input[4])
        }
    }
}

/// Message to enable a feature, sent by the host tools to a paired fob.
#[derive(Clone, Debug, PartialEq)]
pub struct EnableFeatureMessage {
    /// The raw bytes corresponding to an [`EnableFeaturePayload`].
    payload: [u8; 16],

    /// The Ed25519 signature of the payload.
    signature: [u8; 64],
}

impl Message for EnableFeatureMessage {
    const TYPE_ID: u32 = 3;

    fn deserialize_from(input: &[u8; 84]) -> Result<Self, Error> {
        Ok(Self {
            payload: input[StaticRangeIndex::<0, 16>],
            signature: input[StaticRangeIndex::<16, 64>],
        })
    }

    fn serialize_to(self, output: &mut [u8; 84]) -> Result<(), Error> {
        output[StaticRangeIndex::<0, 16>].copy_from(self.payload);
        output[StaticRangeIndex::<16, 64>].copy_from(self.signature);

        Ok(())
    }
}

impl EnableFeatureMessage {
    /// Verifies the authenticity of the feature payload according to a public key,
    /// returning a newly constructed [`EnableFeaturePayload`] if the verification is
    /// successful.
    pub fn verify_payload(&self, key: &PublicKey) -> Result<EnableFeaturePayload, Error> {
        let signature = Signature::from_bytes(&self.signature)?;
        
        key.verify_strict(&self.payload, &signature)?;
        Ok(EnableFeaturePayload::from_bytes(&self.payload))
    }
}

/// Message to start a car, sent by a paired fob.
#[derive(Clone, Debug, PartialEq)]
pub struct StartMessage {
    /// The ID of the car that the fob is paired with.
    pub id: CarID,

    /// The number of features that are enabled on the fob.
    pub num_features: u32
}

impl Message for StartMessage {
    const TYPE_ID: u32 = 4;

    fn deserialize_from(input: &[u8; 84]) -> Result<Self, Error> {
        let id = CarID::new_from_bytes(input[StaticRangeIndex::<0, 4>]);
        let num_features = u32::from_le_bytes(input[StaticRangeIndex::<4, 4>]);

        if num_features > 3 {
            Err(Error::MalformedMessageError)
        } else {
            Ok(Self {
                id,
                num_features,
            })
        }
    }

    fn serialize_to(self, output: &mut [u8; 84]) -> Result<(), Error> {
        output[StaticRangeIndex::<0, 4>].copy_from(self.id.0.to_le_bytes());
        output[StaticRangeIndex::<4, 4>].copy_from(self.num_features.to_le_bytes());
        Ok(())
    }
}

/// Message to share fob-specific information, sent by a paired fob 
/// to an unpaired fob at the conclusion of a successful pairing process.
#[derive(Clone, Debug, PartialEq)]
pub struct PairingFobInfoMessage {
    /// The ID of the car that the fob is paired with.
    pub car_id: CarID,

    /// A randomly generated, unique identifier for the 
    /// newly paired fob.
    pub fob_id: [u8; 32],

    /// The temporary nonce used to encrypt additional 
    /// sensitive data.
    pub extension_nonce: [u8; 24],

    /// The salt assigned to the newly paired fob
    /// for use in key derivation.
    pub salt: [u8; 16]
}

impl Message for PairingFobInfoMessage {
    const TYPE_ID: u32 = 5;

    fn deserialize_from(input: &[u8; 84]) -> Result<Self, Error> {
        Ok(Self {
            car_id: CarID::new_from_bytes(input[StaticRangeIndex::<0, 4>]),
            fob_id: input[StaticRangeIndex::<4, 32>],
            extension_nonce: input[StaticRangeIndex::<36, 24>],
            salt: input[StaticRangeIndex::<60, 16>]
        })
    }

    fn serialize_to(self, output: &mut [u8; 84]) -> Result<(), Error> {
        output[StaticRangeIndex::<0, 4>].copy_from(self.car_id.0.to_le_bytes());
        output[StaticRangeIndex::<4, 32>].copy_from(self.fob_id);
        output[StaticRangeIndex::<36, 24>].copy_from(self.extension_nonce);
        output[StaticRangeIndex::<60, 16>].copy_from(self.salt);

        Ok(())
    }
}

/// Pairing-specific cryptographic material in its raw, unencrypted form.
pub struct PairingCryptoInfoPayload {
    /// The password used to unlock the car.
    pub car_unlock_password: Password,

    /// The symmetric key used for communications
    /// with the car.
    pub car_symmetric_key: Key,
}

impl PairingCryptoInfoPayload {
    /// Parses and constructs a [`PairingCryptoInfoPayload`] from 
    /// an array of 64 bytes.
    pub fn from_bytes(input: &[u8; 64]) -> Self {
        Self {
            car_unlock_password: Password(input[StaticRangeIndex::<0, 32>]),
            car_symmetric_key: Key::new(input[StaticRangeIndex::<32, 32>])
        }
    }

    /// Consumes and serializes the payload into a buffer.
    pub fn serialize(self, output: &mut [u8; 64]) {
        output[StaticRangeIndex::<0, 32>].copy_from(self.car_unlock_password.0);
        output[StaticRangeIndex::<32, 32>].copy_from(self.car_symmetric_key.into());
    }
}

/// Message to share pairing-specific cryptographic material, sent by a paired fob 
/// to an unpaired fob at the conclusion of a successful pairing process.
#[derive(Clone, Debug, PartialEq)]
pub struct PairingCryptoInfoMessage {
    /// The encrypted bytes of a [`PairingCryptoInfoPayload`]
    /// containing the car's cryptographic material.
    payload: [u8; 64],

    /// The authentication tag for the encrypted payload.
    tag: [u8; 16]
}

impl Message for PairingCryptoInfoMessage {
    const TYPE_ID: u32 = 5;

    fn deserialize_from(input: &[u8; 84]) -> Result<Self, Error> {
        Ok(Self {
            payload: input[StaticRangeIndex::<0, 64>],
            tag: input[StaticRangeIndex::<64, 16>]
        })
    }

    fn serialize_to(self, output: &mut [u8; 84]) -> Result<(), Error> {
        output[StaticRangeIndex::<0, 64>].copy_from(self.payload);
        output[StaticRangeIndex::<64, 16>].copy_from(self.tag);

        Ok(())
    }
}

impl PairingCryptoInfoMessage {
    /// Encrypts a [`PairingCryptoInfoPayload`] to create a [`PairingCryptoInfoMessage`]
    /// that can be sent in a packet.
    pub fn new(
        payload: PairingCryptoInfoPayload, 
        key: Key,
        nonce: Nonce,
        car_id: CarID,
        fob_id: [u8; 32]
    ) -> Result<Self, Error> {
        let associated_data = {
            let mut associated_data = [0u8; 36];
            associated_data[StaticRangeIndex::<0, 4>].copy_from(car_id.0.to_le_bytes());
            associated_data[StaticRangeIndex::<4, 32>].copy_from(fob_id);
            associated_data
        };

        let mut result = Self {
            payload: [0u8; 64],
            tag: [0u8; 16]
        };

        payload.serialize(&mut result.payload);

        let cipher = XChaCha20Poly1305::new(&key);
        result.tag = cipher.encrypt_in_place_detached(&nonce, &associated_data, &mut result.payload)?.into();

        Ok(result)
    }

    /// Decrypts and verifies the encrypted payload, returning
    /// a [`PairingCryptoInfoPayload`] on success.
    pub fn into_payload(
        mut self,
        key: Key,
        nonce: Nonce,
        car_id: CarID,
        fob_id: [u8; 32]
    ) -> Result<PairingCryptoInfoPayload, Error> {
        let associated_data = {
            let mut associated_data = [0u8; 36];
            associated_data[StaticRangeIndex::<0, 4>].copy_from(car_id.0.to_le_bytes());
            associated_data[StaticRangeIndex::<4, 32>].copy_from(fob_id);
            associated_data
        };

        let cipher = XChaCha20Poly1305::new(&key);
        cipher.decrypt_in_place_detached(&nonce, &associated_data, &mut self.payload, &self.tag.into())?;

        Ok(PairingCryptoInfoPayload::from_bytes(&self.payload))
    }
}

/// Message to share a car's verifying key, sent by a paired fob
/// to an unpaired fob at the conclusion of a successful pairing process.
#[derive(Clone, Debug, PartialEq)]
pub struct VerifyingKeyMessage {
    pub verifying_key: [u8; 32]
}

impl Message for VerifyingKeyMessage {
    const TYPE_ID: u32 = 6;

    fn deserialize_from(input: &[u8; 84]) -> Result<Self, Error> {
        Ok(Self {
            verifying_key: input[StaticRangeIndex::<0, 32>]
        })
    }

    fn serialize_to(self, output: &mut [u8; 84]) -> Result<(), Error> {
        output[StaticRangeIndex::<0, 32>].copy_from(self.verifying_key);
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::comms::{packet::Key, noncegenerator::Nonce};

    use super::{PairingCryptoInfoMessage, CarID, PairingCryptoInfoPayload, Password};

    #[test]
    fn test_round_trip_crypto_info() {
        let key = Key::new([1u8; 32]);
        let nonce = Nonce::clone_from_slice(&[2u8; 24]);
        let car_id = CarID::new(123);
        let fob_id = [3u8; 32];
        let msg = PairingCryptoInfoMessage::new(
            PairingCryptoInfoPayload { 
                car_unlock_password: Password::new([4u8; 32]), 
                car_symmetric_key: Key::new([5u8; 32])
            },
            key,
            nonce,
            car_id,
            fob_id
        ).expect("Failed to create PairingCryptoInfoMessage");
        let payload = msg.into_payload(key, nonce, car_id, fob_id).expect("Failed to decrypt PairingCryptoInfoMessage");
        assert_eq!(payload.car_unlock_password, Password::new([4u8; 32]));
        assert_eq!(payload.car_symmetric_key, Key::new([5u8; 32]));
    }
}