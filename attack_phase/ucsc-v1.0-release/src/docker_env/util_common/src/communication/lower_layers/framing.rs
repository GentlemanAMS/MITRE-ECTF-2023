//! This module encompasses the framing layer of the BogoStack, which provides framing protocols
//! to use in [`RxChannels`](crate::communication::RxChannel) and [`FramedTxChannels`](FramedTxChannel).
//! Any framing implementation must have channels implementing the aforementioned traits.
//! [`FramedTxChannels`](FramedTxChannel) differ from [`TxChannels`](TxChannel) in that they require
//! framing while [`TxChannels`](TxChannel) do not necessarily require any concept of framing.
//!
//! ## Framing protocols
//! - BogoFraming
//!     - BogoFraming is a very simple framing protocol. Each message begins and ends with one \1 character.
//!     - To prevent conflating \1 characters with the underlying data, the underlying data is hex encoded
//!       and decoded. NULL characters are completely ignored and won't affect the message.
//!     - Helper functions to implement channels using this type of framing are in the [`bogoframing`] module.
//!
//! See the documentation for [`communication`](crate::communication) for a description of full communication
//! stack.

pub mod bogoframing;

use chacha20poly1305::aead::heapless;

use crate::communication::{CommunicationError, TxChannel};

/// A trait to be implemented by all transmission channels in framing protocol implementations.
/// This contains one function to specify the slices that go into the frame to be transmitted.
pub trait FramedTxChannel: TxChannel {
    /// Transmits a frame through the [`TxChannel`] given a closure returning a [`Frame`] or
    /// a [`CommunicationError`]. The const generic, FRAME_CT, must be the number of
    /// slices in the created frame.
    ///
    /// # ERRORS:
    ///
    /// - [`CommunicationError::SendError`] - Occurs when there's no more space
    /// in the frame for the number of slices provided or some error occurs when
    /// sending the frame through the [`TxChannel`].
    fn frame<'a, const FRAME_CT: usize>(
        &mut self,
        frame: impl FnOnce() -> Result<Frame<'a, FRAME_CT>, CommunicationError>,
    ) -> Result<(), CommunicationError>;
}

impl<T: FramedTxChannel> TxChannel for T {
    fn send(&mut self, src: &mut [u8]) -> Result<(), CommunicationError> {
        self.frame::<1>(|| Frame::new().append(src))
    }
}

/// A struct that keeps track of slices of u8's to write as one frame
/// in a [`FramedTxChannel`]. This can be used to write discontiguous
/// pieces of memory into one frame. The const generic ``FRAME_SLICES``
/// indicates the number of slices in the [`Frame`].
#[derive(Default)]
pub struct Frame<'a, const FRAME_SLICES: usize> {
    frame_components: heapless::Vec<&'a [u8], FRAME_SLICES>,
    total_len: usize,
}

impl<'a, const FRAME_SLICES: usize> IntoIterator for Frame<'a, FRAME_SLICES> {
    type Item = &'a [u8];
    type IntoIter = <heapless::Vec<&'a [u8], FRAME_SLICES> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.frame_components.into_iter()
    }
}

impl<'a, const FRAME_CT: usize> Frame<'a, FRAME_CT> {
    /// Instantiates a new [`Frame`]. See the struct documentation for
    /// more information.
    pub fn new() -> Self {
        Frame {
            frame_components: heapless::Vec::new(),
            total_len: 0,
        }
    }

    /// Adds a slice to the frame.
    ///
    /// # ERRORS:
    ///
    /// - [`CommunicationError::InternalError`] - Occurs when there's no more space
    /// in the frame for another slice.
    pub fn append(mut self, buff: &'a [u8]) -> Result<Self, CommunicationError> {
        match self.frame_components.push(buff) {
            Ok(_) => {
                self.total_len += buff.len();

                Ok(self)
            }
            Err(_) => Err(CommunicationError::InternalError),
        }
    }

    /// Gets the length of the frame in bytes.
    pub fn len(&self) -> usize {
        self.total_len
    }

    /// Checks if the [`Frame`] is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
