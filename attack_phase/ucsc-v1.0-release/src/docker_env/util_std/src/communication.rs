//! This module contains traits to implement the BogoStack and error structs. It also contains a concrete
//! implementation of the application layer. See the below description of the BogoStack for more information.
//!
//! ## BogoStack
//!
//! The BogoStack consists of three layers.
//! - The framing layer
//!     - The framing layer is responsible for turning a stream of data into frames. See the
//!       [`framing`](lower_layers::framing) module for the traits and structs provided to
//!       facilitate the implementation of this layer.
//! - The encryption and integrity layer
//!     - This layer is responsible for providing secure and authenticated methods of transportation.
//!       Implementations of this part of the BogoStack are provided in the [`crypto`](lower_layers::crypto)
//!       module. See that module for more detail on the traits and structs provided for this layer.
//! - The application layer
//!     - The application layer is the layer responsible for incorporating the lower two layers together.
//!       This crate provides an implementation of this layer through the [`VerifiedFramedTcpSocket`] struct.

pub(crate) mod framed_tcp;
mod verified_framed_tcp;

pub use ucsc_ectf_util_common::communication::*;
pub use verified_framed_tcp::*;
