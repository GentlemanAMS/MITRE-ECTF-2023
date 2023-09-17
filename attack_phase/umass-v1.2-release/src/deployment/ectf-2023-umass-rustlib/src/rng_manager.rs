use rand_chacha::ChaCha12Rng;
use rand_core::{RngCore, SeedableRng};

use crate::mitre_hal::{EEPROMRead, EEPROMProgram, timer_get};

// Don't use AtomicRefCell because init_rng stack becomes too big
pub(crate) static mut RNG: Option<ChaCha12Rng> = None;

const RNG_SEED_U32_LEN: usize = 32/core::mem::size_of::<u32>();
const RNG_SEED_LOC: u32 = 0x80;

// WARNING: one temp RNG instace is created on the stack
// Using AtomicRefCell leads to *two*
pub fn init_rng() {
    let mut seed: [u32; RNG_SEED_U32_LEN] = [0; RNG_SEED_U32_LEN];

    unsafe {
        EEPROMRead(seed.as_mut_ptr(), RNG_SEED_LOC, RNG_SEED_U32_LEN.try_into().unwrap());
        let seed_u8_slice = bytemuck::bytes_of(&seed);
        RNG = Some(ChaCha12Rng::from_seed(seed_u8_slice.try_into().unwrap()));
    }
    // Key erasure concept: ensure randomness changes on every boot
    // Timing is too predictable at init for entropy injection to be useful
    overwrite_seed();
}
fn overwrite_seed() {
    let mut seed: [u32; RNG_SEED_U32_LEN] = [0; RNG_SEED_U32_LEN];
    let seed_u8_slice = bytemuck::bytes_of_mut(&mut seed);
    unsafe {
        RNG.as_mut().unwrap().fill_bytes(seed_u8_slice);
        EEPROMProgram(seed.as_ptr(), RNG_SEED_LOC, RNG_SEED_U32_LEN.try_into().unwrap());
    }
}
pub fn ingest_entropy() {
    let entropy = unsafe {timer_get()};
    let mut temp_rng = ChaCha12Rng::seed_from_u64(entropy);

    let mut new_seed: [u32; RNG_SEED_U32_LEN] = [0; RNG_SEED_U32_LEN];
    let new_seed_u8_slice = bytemuck::bytes_of_mut(&mut new_seed);
    unsafe {
        RNG.as_mut().unwrap().fill_bytes(new_seed_u8_slice);
    }
    for i in 0..RNG_SEED_U32_LEN {
        new_seed[i] ^= temp_rng.next_u32();
    }

    let new_seed_u8_slice = bytemuck::bytes_of_mut(&mut new_seed);
    temp_rng = ChaCha12Rng::from_seed(new_seed_u8_slice.try_into().unwrap());
    temp_rng.fill_bytes(new_seed_u8_slice);
    unsafe {
        EEPROMProgram(new_seed.as_ptr(), RNG_SEED_LOC, RNG_SEED_U32_LEN.try_into().unwrap());
        RNG = Some(temp_rng);
    }
}