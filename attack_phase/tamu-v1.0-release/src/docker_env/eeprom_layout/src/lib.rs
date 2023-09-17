#![no_std]

extern crate static_assertions as sa;
pub mod car;
pub mod fob;
mod primitive;
use blake2::digest::generic_array::GenericArray;
use blake2::digest::typenum::U32;
use blake2::{Blake2s256, Digest};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
pub use primitive::Primitive;

pub type Hash = GenericArray<u8, U32>;

#[repr(C)]
pub struct Hashed<T: Primitive> {
    pub data: T,
    pub hash: Hash,
}

unsafe impl<T: Primitive> Primitive for Hashed<T> {
    const OFFSET: usize = T::OFFSET;
}

impl<T: Primitive> Hashed<T> {
    pub fn new(data: T) -> Self {
        let hash = oneshot_hash(data.as_bytes());
        Self { data, hash }
    }
}

fn oneshot_hash(xs: &[u8]) -> Hash {
    let mut h = Blake2s256::new();
    h.update(xs);
    h.finalize()
}

pub type Seed = [u8; 32];

pub const PADDED_PUBLIC_KEY_LEN: usize = 68;
pub const SEC1_PUBLIC_KEY_LEN: usize = 65;
pub const PRIVATE_KEY_LEN: usize = 32;

pub struct PubKey(pub [u8; PADDED_PUBLIC_KEY_LEN]);

impl PubKey {
    pub fn load(&self) -> VerifyingKey {
        VerifyingKey::from_sec1_bytes(&self.0[..SEC1_PUBLIC_KEY_LEN]).unwrap()
    }
}

pub struct PrivKey(pub [u8; PRIVATE_KEY_LEN]);

impl PrivKey {
    pub fn load(&self) -> SigningKey {
        SigningKey::from_bytes(&self.0).unwrap()
    }
}

#[repr(C, align(4))]
pub struct EnablePackage {
    pub car_id: u32,
    pub feature_number: u32,
    pub hash: Hash,
    pub signature: Signature,
}
impl_primitive!(0, EnablePackage);
