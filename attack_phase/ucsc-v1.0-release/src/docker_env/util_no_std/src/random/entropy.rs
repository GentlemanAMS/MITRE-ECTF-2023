//! This module contains an interface to gather entropy and hash the entropy sources together.

mod adc;
mod clock_drift;
mod secret;
mod uninit_memory;

pub(crate) use adc::Adc;
pub(crate) use clock_drift::ClockDrift;
pub(crate) use secret::Secret;
pub(crate) use uninit_memory::UninitMemory;

use crate::RuntimePeripherals;
use sha3::{Digest, Sha3_256};

/// The size of the hashed entropy. 256 bits = 32 bytes.
const ENTROPY_HASH_SIZE: usize = 32;

/// A trait for all entropy sources.
pub(crate) trait EntropySource {
    /// Initializes the internal state of the entropy source. May block to gather entropy.
    ///
    /// IMPORTANT NOTE: This function must call the next entropy source's `init()` function.
    fn init(peripherals: &mut RuntimePeripherals) -> Self;

    /// Adds entropy from the entropy source to a hasher.
    ///
    /// IMPORTANT NOTE: This function must call the next entropy source's `add_to_hasher()` function.
    fn add_to_hasher(&self, hasher: &mut Sha3_256);
}

// We implement this trait for () so that we can use it to end the list of entropy sources.
impl EntropySource for () {
    fn init(_peripherals: &mut RuntimePeripherals) {}
    fn add_to_hasher(&self, _hasher: &mut Sha3_256) {}
}

/// A hasher that concatenates entropy sources together and hashes the result.
pub(crate) struct EntropyHasher<T: EntropySource> {
    /// The sources of entropy to hash.
    entropy: T,
}

impl<T: EntropySource> EntropyHasher<T> {
    /// Initializes the entropy hasher, gathering entropy from all of the inputted sources.
    pub(crate) fn new(peripherals: &mut RuntimePeripherals) -> Self {
        EntropyHasher {
            entropy: T::init(peripherals),
        }
    }

    /// Concatenates entropy sources together and hashes the result.
    pub(crate) fn hash(&self) -> [u8; ENTROPY_HASH_SIZE] {
        let mut hasher = Sha3_256::new();
        self.entropy.add_to_hasher(&mut hasher);
        hasher.finalize().into()
    }
}
