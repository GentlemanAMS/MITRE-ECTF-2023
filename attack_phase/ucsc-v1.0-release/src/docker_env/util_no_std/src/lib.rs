//! This crate contains utility modules for use by the car and key fob.

#![warn(missing_docs)]
#![no_std]

pub mod button;
pub mod communication;
pub mod eeprom;
pub mod features;
pub mod hib;
pub mod timer;

pub(crate) mod random;

mod runtime;

pub use runtime::*;
pub use ucsc_ectf_util_common::messages;
