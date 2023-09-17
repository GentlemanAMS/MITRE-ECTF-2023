//! This module contains submodules for the layers below the application layer of the BogoStack, which
//! are the [`encryption and integrity layer`](crypto) and the [`framing layer`](framing).
//!
//! See the documentation for [`communication`](crate::communication) for a description of the BogoStack
//! and more info on the layers of the BogoStack.

pub mod crypto;
pub mod framing;
