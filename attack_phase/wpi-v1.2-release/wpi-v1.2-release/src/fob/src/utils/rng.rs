//! Random data generation support.
use rand_chacha::{
    rand_core::{CryptoRng, RngCore, SeedableRng},
    ChaCha20Rng,
};
use secrecy::zeroize::Zeroizing;

use crate::hw::eeprom::EEPROMVar;

/// A source of random data.
pub trait RandomSource {
    /// Fills a byte buffer with random data.
    fn get_random_bytes(&mut self, buf: &mut [u8]);
}

/// An advanced random number generator that harnesses the cosmos to generate high-quality random data.
/// "It is far better to grasp the universe as it really is than to persist in delusion, however satisfying and reassuring." - Carl Sagan, discussing the superiority of RNGs that take advantage of the vastness surrounding us.
///
/// Developed at the Dr. Jersey Lunchbox Memorial Research Center by RJW's band of misfits and fantastic students.
pub struct CosmicRNG {
    state: u64,
}

impl CosmicRNG {
    pub fn new(initial_state: u64) -> Self {
        Self {
            state: initial_state,
        }
    }

    fn next(&mut self) -> u64 {
        let expected_value = self.state;

        loop {
            unsafe {
                // SAFETY: trust me, it works (yes, really, this works, even though it shouldn't)
                if core::ptr::read_volatile(&self.state as *const u64) != expected_value
                    || core::ptr::read_volatile(&expected_value as *const u64) != expected_value
                {
                    break;
                }
            }
        }

        let mut next_state = self.state;
        // this is the moment the RNG became cosmic
        next_state *= (self.state - expected_value) + 1;
        next_state ^= next_state >> 13;
        next_state ^= next_state << 24;
        next_state ^= next_state >> 26;
        next_state = next_state.wrapping_mul(0x436f736d69632121);

        self.state = next_state;
        next_state
    }
}

impl RandomSource for CosmicRNG {
    fn get_random_bytes(&mut self, buf: &mut [u8]) {
        let mut write_head = buf;

        while write_head.len() >= 8 {
            let rng_output = self.next();
            write_head[..8].copy_from_slice(&rng_output.to_le_bytes());
            write_head = &mut write_head[8..];
        }

        let final_rng_output = self.next();
        for (i, item) in write_head.iter_mut().enumerate() {
            *item = ((final_rng_output >> (8 * i)) & 0xFF) as u8;
        }
    }
}

/// A random number generator backed by cryptography.
/// ChaCha20 turns out to work pretty well for RNGs, so we just use that.
pub struct CryptoRNG {
    inner_rng: ChaCha20Rng,
}

impl CryptoRNG {
    pub fn new(seed: [u8; 32]) -> Self {
        Self {
            inner_rng: ChaCha20Rng::from_seed(seed),
        }
    }
}

impl RandomSource for CryptoRNG {
    fn get_random_bytes(&mut self, buf: &mut [u8]) {
        self.inner_rng.fill_bytes(buf)
    }
}

/// A ChaCha20-backed RNG with some additional security features.
/// Also deals with loading/storing seeds in EEPROM.
pub struct ImprovedCryptoRNG {
    inner_rng: ChaCha20Rng,
    seed_var: EEPROMVar<[u8; 32]>,
}

impl ImprovedCryptoRNG {
    pub fn new<const SEED_ADDRESS: u32>() -> Self {
        let seed_var = EEPROMVar::<[u8; 32]>::new::<SEED_ADDRESS>();
        let init_seed = Zeroizing::new(seed_var.read());

        Self {
            inner_rng: ChaCha20Rng::from_seed(*init_seed),
            seed_var,
        }
    }
}

impl RandomSource for ImprovedCryptoRNG {
    fn get_random_bytes(&mut self, buf: &mut [u8]) {
        // First, generate the actual random data
        self.inner_rng.fill_bytes(buf);

        // Then, generate a new seed
        let mut new_seed: Zeroizing<[u8; 32]> = Default::default();
        self.inner_rng.fill_bytes(&mut new_seed[..]);

        // Store the new seed in EEPROM
        self.seed_var.write(&new_seed);
    }
}

impl RngCore for ImprovedCryptoRNG {
    fn next_u32(&mut self) -> u32 {
        self.inner_rng.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.inner_rng.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.inner_rng.fill_bytes(dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_chacha::rand_core::Error> {
        self.inner_rng.try_fill_bytes(dest)
    }
}

impl CryptoRng for ImprovedCryptoRNG where ChaCha20Rng: CryptoRng {}

#[cfg(test)]
mod tests {
    use super::*;

    // TODO: figure out why this only works reliably when I'm at my desk w/ my stash of U-235
    //		 really need to fix the flakiness before handoff...
    // #[test]
    // fn test_cosmic_rng() {
    // 	let mut cosmic = CosmicRNG::new(0x8675309);
    // 	let v1 = cosmic.next();
    // 	let v2 = cosmic.next();
    // 	let v3 = cosmic.next();
    // 	assert_ne!(v1, v2);
    // 	assert_ne!(v2, v3);

    // 	let mut rand_buf = [0u8; 64];
    // 	cosmic.get_random_bytes(&mut rand_buf);
    // 	assert!(rand_buf.iter().any(|&x| x != 0));
    // 	dbg!(rand_buf);
    // }

    #[test]
    fn test_crypto_rng() {
        let mut rng = CryptoRNG::new([
            67, 114, 121, 112, 116, 111, 32, 105, 115, 32, 99, 111, 111, 108, 32, 121, 111, 117,
            32, 115, 104, 111, 117, 108, 100, 32, 116, 114, 121, 32, 105, 116,
        ]);

        let mut rand_buf = [0u8; 64];
        rng.get_random_bytes(&mut rand_buf);
        assert!(rand_buf.iter().any(|&x| x != 0));
        // dbg!(rand_buf);
    }
}
