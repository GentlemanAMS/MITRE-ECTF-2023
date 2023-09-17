extern crate static_assertions as sa;
use core::mem::size_of;
use cortex_m::asm::delay;
use crate::error::{Error, Result};
use blake2::{
    digest::{consts::U32, generic_array::GenericArray},
    Blake2s256, Digest,
};
use chacha20poly1305::{
    aead::{AeadInPlace, NewAead},
    Key, Tag, XChaCha20Poly1305, XNonce,
};
use rand_chacha::{rand_core::RngCore, ChaChaRng};
use eeprom_layout::{Primitive, impl_primitive};
use p256::ecdsa::{Signature, SigningKey, signature::Signer};

pub type BlakeHash = GenericArray<u8, U32>;

pub fn verify_hash(data: &[u8], hash: &BlakeHash, r: &mut ChaChaRng) -> Result<()> {
    let rhs = oneshot_hash(data);
    jitter(r);
    if hash != &rhs {
        Err(Error::InvalidHash)
    } else {
        Ok(())
    }
}

pub fn oneshot_hash(data: &[u8]) -> BlakeHash {
    let mut hasher = Blake2s256::new();
    hasher.update(data);
    hasher.finalize()
}

pub fn oneshot_decrypt(data: &mut [u8], key: &Key, tag: &Tag, nonce: &XNonce) -> Result<()> {
    XChaCha20Poly1305::new(key)
        .decrypt_in_place_detached(nonce, b"", data, tag)
        .map_err(|_| Error::DecryptionFailure)
}

pub fn oneshot_encrypt(data: &mut [u8], key: &Key, nonce: &XNonce) -> Result<Tag> {
    XChaCha20Poly1305::new(key)
        .encrypt_in_place_detached(nonce, b"", data)
        .map_err(|_| Error::EncryptionFailure)
}

pub fn jitter(rng: &mut ChaChaRng) {
    delay(rng.next_u32() & 0xFF);
}

pub fn generate_nonce(r: &mut ChaChaRng) -> [u8; size_of::<XNonce>()] {
    let mut nonce = [0u8; size_of::<XNonce>()];
    r.fill_bytes(&mut nonce);
    nonce
}

#[repr(C, align(4))]
pub struct Challenge {
    pub nonce: [u8; size_of::<XNonce>()],
    pub signature: Signature,
}

impl Challenge {
    pub fn new(r: &mut ChaChaRng, signing_key: &SigningKey) -> Self {
        let nonce = generate_nonce(r);

        Self {
            nonce,
            signature: signing_key.sign(&nonce),
        }
    }

    pub fn generate_nonce(&mut self, r: &mut ChaChaRng) {
        generate_nonce(r);
    }
}

impl_primitive!(0, Challenge);

#[repr(C, align(4))]
pub struct FeaturePackage {
    pub enabled_features: [u8; 4],
    pub hash: BlakeHash,
    pub signature: Signature,
}
impl_primitive!(0, FeaturePackage);

