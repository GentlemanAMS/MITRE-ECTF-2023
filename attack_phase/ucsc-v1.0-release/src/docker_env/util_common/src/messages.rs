//! This module is responsible for providing [`serde`] serializable/deserializable structs
//! for messages sent between the car, key fob, and host tools.

use k256::{
    ecdsa::{signature::Verifier, Signature, VerifyingKey},
    elliptic_curve::sec1::FromEncodedPoint,
    EncodedPoint, PublicKey,
};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub use chacha20poly1305::Key;
pub use heapless;

/// The car ID type
pub type CarId = u32;

/// The feature number type
pub type FeatureNumber = u32;

/// The type for a nonce/challenge.
pub type Nonce = [u8; 16];

/// The number of features.
pub const NUM_FEATURES: usize = 3;

/// This enum represents all possible messages that can be sent across UART0 between
/// host tools and a car or a paired key fob.
#[non_exhaustive]
#[derive(Serialize, Deserialize)]
pub enum Uart0Message<'a> {
    /// A message sent from the enable feature host tool to a paired key fob
    /// containing a signed feature associated with a car, which is sent.
    ///
    /// See [`EnableFeatureMessage`] for more details.
    EnableFeatureRequest(EnableFeatureMessage<'a>),

    /// The response sent from a paired key fob to the enable feature host tool
    /// in response to an [`Uart0Message::EnableFeatureRequest`].
    EnableFeatureResponse(HostToolAck),

    /// A message sent from a car to the unlock host tool containing
    /// the unlock message, and up to 3 feature messages, which are sent
    /// upon a successful unlock.
    ///
    /// See [`UnlockMessage`] for more details.
    #[serde(borrow)]
    HostUnlock(UnlockMessage<'a>),

    /// A message sent from the pairing host tool to a paired key fob to initiate
    /// the pairing sequence if this pin was correct.
    ///
    /// See [`PairingPin`] for more details.
    PairingPin(PairingPin),

    /// The response sent from an unpaired key fob to the pairing host tool in response
    /// to a [`Uart0Message::PairingPin`].
    ///
    /// See [`HostToolAck`] for more details.
    PairingPinResponse(HostToolAck),
}

/// This enum represents all possible messages that can be sent across UART1 between
/// a car and its paired key fob or between a paired key fob and an unpaired key fob.
#[non_exhaustive]
#[derive(Serialize, Deserialize)]
pub enum Uart1Message<'a> {
    /// A message sent from a paired key fob to its car to signal the start of an unlock
    /// sequence.
    ///
    /// See [`UnlockRequest`] for more details.
    UnlockRequest(UnlockRequest),

    /// A unique challenge sent from a car to its paired key fob to guarantee freshness
    /// for an unlock sequence.
    ///
    /// See [`UnlockChallenge`] for more details.
    UnlockChallenge(UnlockChallenge),

    /// The response to a challenge sent from a car containing the original challenge
    /// along with additional data to unlock the car.
    ///
    /// See [`UnlockChallengeResponse`] for more details.
    UnlockChallengeResponse(UnlockChallengeResponse<'a>),

    /// A message sent either from a paired key fob to an unpaired key fob and the other
    /// way around to establish a shared secret to symmetrically encrypt the pairing
    /// sequence.
    ///
    /// See [`DiffieHellmanMessage`] for more details.
    #[serde(borrow)]
    DiffieHellman(DiffieHellmanMessage<'a>),

    /// A message sent by a paired key fob to an unpaired key fob to initiate the pairing
    /// sequence.
    ///
    /// See [`PairingRequest`] for more details.
    PairingRequest(PairingRequest),

    /// A unique challenge sent from a paired key fob to an unpaired key fob to guarantee
    /// freshness for a pairing sequence.
    ///
    /// See [`PairingChallenge`] for more details.
    PairingChallenge(PairingChallenge),

    /// The response to a challenge sent from a paired key fob containing the original challenge
    /// along with additional data to complete the pairing sequence.
    ///
    /// See [`PairingChallengeResponse`] for more details.
    PairingChallengeResponse(PairingChallengeResponse),
}

/// The message to send to a car to signal the start of an unlock seequence.
/// It contains the car ID of the car to be unlocked.
#[derive(Serialize, Deserialize)]
pub struct UnlockRequest(pub CarId);

/// The message to send to a paired key fob that initiated an unlock sequence
/// using an [`UnlockRequest`]. This message contains a [`Nonce`] to prevent
/// replay attacks.
#[derive(Serialize, Deserialize)]
pub struct UnlockChallenge {
    /// The ID of the car to be unlocked.
    pub car_id: CarId,

    /// The unique 128-bit challenge to use to maintain freshness.
    pub challenge: Nonce,
}

/// A packaged feature, containing the Car ID and Feature Number.
#[derive(Serialize, Deserialize, Debug)]
pub struct PackagedFeatureUnsigned {
    /// The ID of the car this feature is meant for.
    pub car_id: CarId,

    /// The number for the feature to enable on the linked car
    pub feature_number: FeatureNumber,
}

/// A signed packaged feature associated with the car it's tied to.
/// The signature guarantees that it's not tampered with.
#[derive(Serialize, Deserialize, Debug)]
pub struct PackagedFeatureSigned<'a> {
    /// The helper struct containing the Car ID and Feature Number.
    pub packaged_feature: PackagedFeatureUnsigned,

    /// A signature for the car ID and feature number encoded in DER format.
    pub signature: &'a [u8],
}

/// The response to send for an [`UnlockChallenge`]. It contains the [`Nonce`]
/// from the challenge to prevent replay attacks. See the fields of this struct
/// for more information.
#[derive(Serialize, Deserialize)]
pub struct UnlockChallengeResponse<'a> {
    /// The ID of the car to be unlocked.
    pub car_id: CarId,

    /// The [`Nonce`] in the [`UnlockChallenge`] sent before this response.
    pub challenge_response: Nonce,

    /// A list of features that are enabled for this car.
    #[serde(borrow)]
    pub features: heapless::Vec<PackagedFeatureSigned<'a>, NUM_FEATURES>,
}

/// The message containing the unlock secret, the feature secrets of any enabled features on the
/// car, and the car ID to be sent to the unlock host tool on a successful unlock.
#[derive(Serialize, Deserialize)]
pub struct UnlockMessage<'a> {
    /// The unlock secret for the car.
    pub unlock_msg: &'a [u8],

    /// The enabled features on the car.
    pub feature_nums: heapless::Vec<FeatureNumber, NUM_FEATURES>,

    /// The feature secrets for the enabled secrets on the car.
    pub feature_msgs: heapless::Vec<&'a [u8], NUM_FEATURES>,

    /// The car ID.
    pub car_id: CarId,
}

/// A message containing a signed packaged feature to enable a feature
/// on a car. It is sent to a paired key fob associated with a car.
#[derive(Serialize, Deserialize)]
pub struct EnableFeatureMessage<'a>(#[serde(borrow)] pub PackagedFeatureSigned<'a>);

/// A struct containing the pairing pin needed to initiate a pairing
/// sequence.
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct PairingPin(pub u32);

/// An acknowledgement to a request sent by a host tool.
/// The contained boolean is true if the requested operation
/// was a success.
#[derive(Serialize, Deserialize)]
pub struct HostToolAck(pub bool);

/// A signed public key.
#[derive(Serialize, Deserialize)]
pub struct VerifiedPublicKey<'a> {
    /// The public key in SEC1 format.
    pub public_key: &'a [u8],

    /// The signature authenticating ``public_key`` in byte format.
    pub public_key_signature: &'a [u8],
}

impl VerifiedPublicKey<'_> {
    /// Verifies and gets the public key.
    pub fn verify_and_get_key(&self, verifying_key: &VerifyingKey) -> Option<PublicKey> {
        // Verify key.
        let public_key_signature = Signature::try_from(self.public_key_signature).ok()?;

        verifying_key
            .verify(self.public_key, &public_key_signature)
            .ok()?;

        // Get key.
        PublicKey::from_encoded_point(&EncodedPoint::from_bytes(self.public_key).ok()?).into()
    }
}

/// A message containing the public key associated with the ephemeral secret and a
/// key-signing public key to verify the public key's authenticity. The public key
/// associated with the ephemeral secret is signed by the private key paired with
/// the key-signing public key.
#[derive(Serialize, Deserialize)]
pub struct DiffieHellmanMessage<'a> {
    /// The public key associated with the ephermeral secret signed with the private
    /// key associated with ``key_signing_public_key``.
    #[serde(borrow)]
    pub ephemeral_public_key: VerifiedPublicKey<'a>,

    /// The public key associated with the private key that signed ``ephemeral_public_key``.
    /// This key is signed with a private key thrown away at the end of the build process,
    /// but can be verified on all key fobs.
    #[serde(borrow)]
    pub key_signing_public_key: VerifiedPublicKey<'a>,
}

/// A message to send to an unpaired key fob to initiate a pairing request
/// containing a [`Nonce`].
#[derive(Serialize, Deserialize)]
pub struct PairingRequest(pub Nonce);

/// The message to send to a paired key fob that initiated a pairing sequence
/// using a [`PairingRequest`]. The challenge is to prevent replay attacks.
#[derive(Serialize, Deserialize)]
pub struct PairingChallenge {
    /// The [`Nonce`] from the original [`PairingRequest`] sent.
    pub request_nonce: Nonce,

    /// The unique challenge for the paired key fob to respond to for freshness.
    pub challenge: Nonce,
}

/// The response to send for a [`PairingChallenge`]. It contains the [`Nonce`]
/// from the challenge to prevent replay attacks. See the fields of this struct
/// for more information.
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct PairingChallengeResponse {
    /// The [`Nonce`] sent in the original [`PairingRequest`] to the
    /// unpaired key fob.
    pub request_nonce: Nonce,

    /// The [`Nonce`] from the challenge given by the unpaired key fob.
    pub challenge_response: Nonce,

    /// The key to encrypt messages sent from the key fob that is being
    /// paired.
    pub key_fob_encryption_key: Key,

    /// The key to decrypt messages sent from the car that the key fob
    /// will be paired to.
    pub car_encryption_key: Key,

    /// The ID of the car the key fob will be paired to.
    pub car_id: CarId,

    /// The pairing PIN to use to pair future key fobs.
    pub pairing_pin: PairingPin,
}
