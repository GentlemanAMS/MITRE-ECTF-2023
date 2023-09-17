//! This module contains an interface to generate random numbers from two CSPRNGS: the main CSPRNG
//! and the secondary CSPRNG.
//!
//! The main CSPRNG is to be used by the runtime to generate random numbers and internally by this
//! crate when the runtime is known to be initialized. Initialization of this CSPRNG will block to
//! gather entropy.
//!
//! The secondary CSPRNG is to be used internally by this crate where the main CSPRNG has not been
//! initialized yet. Initialization of this CSPRNG does not need to block to gather entropy. Uses
//! the same seed across reboots.

mod entropy;

use core::cell::RefCell;
use cortex_m::interrupt::{self, Mutex};
use once_cell::sync::OnceCell;

use rand_chacha::{
    rand_core::{RngCore, SeedableRng},
    ChaCha20Rng,
};

use self::entropy::{Adc, ClockDrift, EntropyHasher, Secret, UninitMemory};
use crate::RuntimePeripherals;

static MAIN_CSPRNG: OnceCell<Mutex<RefCell<ChaCha20Rng>>> = OnceCell::new();
static SECONDARY_CSPRNG: OnceCell<Mutex<RefCell<ChaCha20Rng>>> = OnceCell::new();

/// Initializes the secondary and main CSPRNG. The initialization of the main CSPRNG will block while
/// gathering entropy. The secondary CSPRNG does not need to block while gathering entropy. The
/// secondary CSPRNG will have been initialized by the time the main CSPRNG is to be initialized.
///
/// Will do nothing if called more than once.
pub(crate) fn init_rng(peripherals: &mut RuntimePeripherals) {
    SECONDARY_CSPRNG.get_or_init(|| {
        Mutex::new(RefCell::new(ChaCha20Rng::from_seed(
            EntropyHasher::<Secret<()>>::new(peripherals).hash(),
        )))
    });

    MAIN_CSPRNG.get_or_init(|| {
        Mutex::new(RefCell::new(ChaCha20Rng::from_seed(
            EntropyHasher::<UninitMemory<Secret<Adc<ClockDrift<()>>>>>::new(peripherals).hash(),
        )))
    });
}

/// Fills a slice with random bytes from the main CSPRNG.
///
/// # Panics
///
/// Panics if the main CSPRNG has not been initialized yet.
pub(crate) fn fill_rand_slice(dest: &mut [u8]) {
    interrupt::free(|c| {
        MAIN_CSPRNG
            .get()
            .expect("The main CSPRNG has not been initialized yet. Initialize it first with init_rng().")
            .borrow(c)
            .borrow_mut()
            .fill_bytes(dest);
    });
}

/// Fills a slice with random bytes from the secondary CSPRNG.
///
/// # Danger
///
/// The seed for this CSPRNG is the same across reboots.
///
/// # Panics
///
/// Panics if the secondary CSPRNG has not been initialized yet.
pub(crate) fn fill_rand_slice_secondary(dest: &mut [u8]) {
    interrupt::free(|c| {
        SECONDARY_CSPRNG
            .get()
            .expect("The secondary CSPRNG has not been initialized yet. Initialize it first with init_secondary_rng().")
            .borrow(c)
            .borrow_mut()
            .fill_bytes(dest);
    });
}
