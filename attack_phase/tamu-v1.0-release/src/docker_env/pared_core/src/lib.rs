#![no_std]

pub mod crypto;
pub mod error;
pub mod peripherals;

pub use crate::error::Result;
pub use crate::peripherals::Peripherals;

use crate::crypto::{BlakeHash, oneshot_hash};

pub fn hash_text_section() -> BlakeHash {
    extern "C" {
        #[allow(improper_ctypes)]
        static mut _stext: ();
        #[allow(improper_ctypes)]
        static mut __etext: ();
    }
    let text = unsafe {
        let start = core::ptr::addr_of!(_stext) as *const u8;
        let end = core::ptr::addr_of!(__etext) as *const u8;
        let len = end as usize - start as usize;
        core::slice::from_raw_parts(start, len)
    };
    oneshot_hash(text)
}

