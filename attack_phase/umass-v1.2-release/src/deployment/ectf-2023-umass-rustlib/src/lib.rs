#![no_std]

pub mod array_type;
pub mod board_link;
pub mod car_main;
pub mod constants;
pub mod fob_main;
pub mod mitre_hal;
pub mod packet_types;
pub mod rng_manager;
pub mod scramish;

use constants::*;
use mitre_hal::{GPIOPinWrite, SysCtlDelay};

use core::{panic::PanicInfo};

pub static FEATURE_SIG_PUBKEY: &[u8] = include_bytes!("../../feature_sign.pub");

extern "C" {
    pub static FOB_STATE_PTR: u32;
}

const NUM_FEATURES: usize = 3;

#[cfg(all(not(test), not(feature = "std")))]
#[panic_handler]
fn panic_handler(_panic: &PanicInfo<'_>) -> ! {
    unsafe {
        GPIOPinWrite(GPIO_PORTF_BASE,
            GPIO_PIN_1 | GPIO_PIN_2 | GPIO_PIN_3,
            GPIO_PIN_1
        ); // 123 rbg
    }
    // TODO: maybe print out panic information on debug?
    loop {}
}
#[cfg(feature = "std")]
extern crate std;

pub use car_main::car_main;
pub use fob_main::fob_main;

#[inline(always)]
pub(crate) fn sleep(count: u32) {
    unsafe {SysCtlDelay(count)}
}
