//! Top-level module for core functionality.
#![cfg_attr(test, allow(unused_imports))]
#![cfg_attr(not(test), no_std)]
#![allow(clippy::let_unit_value)]
#![warn(clippy::panic)]
#![warn(clippy::expect_used)]
#![warn(clippy::unwrap_used)]
#![deny(unused_results)]

pub mod comms;
pub mod error;
pub mod hw;
pub mod security;
pub mod tivaware;
pub mod utils;

#[cfg(test)]
pub mod test;
