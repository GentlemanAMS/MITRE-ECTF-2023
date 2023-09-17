//! The functions in this module are to help implement BogoFraming based [`FramedTxChannels`](super::FramedTxChannel) and
//! [`RxChannels`](crate::communication::RxChannel).
//!
//! - BogoFraming
//!     - BogoFraming is a very simple framing protocol. Each message begins and ends with one \1 character.
//!     - To prevent conflating \1 characters with the underlying data, the underlying data is hex encoded
//!       and decoded. NULL characters are completely ignored and won't affect the message.
//!     - Helper functions to implement channels using this type of framing are in the [`bogoframing`](self) module.

use super::Frame;
use crate::communication::{self, CommunicationError, Timer};

#[derive(Copy, Clone, PartialEq, Eq)]
enum TimeoutType {
    ByteLevel,
    FrameLevel,
}

/// Receives a bogoframe. [`TimeoutType`] determines whether the timeout resets after
/// receiving a byte or whether the timemout applies to receiving the entire frame.
fn recv_bogoframe<T, U: Timer>(
    read_arg: &mut T,
    dest: &mut [u8],
    timer: &mut U,
    mut read_fn: impl FnMut(&mut T) -> communication::Result<u8>,
    min_message_len: usize,
    timeout_type: TimeoutType,
) -> communication::Result<usize> {
    /// Reads a hex nibble, returning ``Ok(None)`` if \1 character is encountered,
    /// or the hex digit as a number if successful, or an error upon receiving
    /// an invalid character or timeout. This function ignores any NULL characters
    /// by reading again.
    fn read_hex_nibble<T, U: Timer>(
        read_fn_arg: &mut T,
        mut read_fn: impl FnMut(&mut T) -> communication::Result<u8>,
        timer: &mut U,
        timeout_type: TimeoutType,
    ) -> communication::Result<Option<u8>> {
        let nibble = loop {
            if timer.poll() {
                break Err(CommunicationError::RecvError);
            }

            if let Ok(read) = read_fn(read_fn_arg) {
                match read {
                    b'\0' => continue,
                    1 => break Ok(None),
                    b'0'..=b'9' => break Ok(Some(read - b'0')),
                    b'a'..=b'f' => break Ok(Some(read - b'a' + 10)),
                    _ => break Err(CommunicationError::RecvError),
                };
            }
        };

        // Reset the timer if the timeout is per byte only if a valid byte was encountered.
        if nibble.is_ok() && timeout_type == TimeoutType::ByteLevel {
            timer.reset();
        }

        nibble
    }

    if dest.len() < min_message_len {
        return Err(CommunicationError::RecvError);
    }

    // First, read and discard data until a \1 character is found because any data that's not \1
    // is garbage, keeping the timeout in mind.
    loop {
        if timer.poll() {
            return Err(CommunicationError::RecvError);
        }

        if let Ok(n) = read_fn(read_arg) {
            // Reset the timer if the timeout is per byte.
            if timeout_type == TimeoutType::ByteLevel {
                timer.reset();
            }

            if n == 1 {
                break;
            }
        }
    }

    // Once a \1 is found, keep reading until we find a non-\1 and non-NULL character to indicate the start of
    // a message, keeping the timeout in mind. We can do this because a frame must contain at least
    // 1 character.
    let mut first_nibble = loop {
        // If we find an non-hex, non-\1, or non-NULL character, we return an error.
        // If it's a \1 character, we continue.
        // If it's a hex character, we return the number it represents.
        if let Some(n) = read_hex_nibble(read_arg, &mut read_fn, timer, timeout_type)? {
            break Some(n);
        }
    };

    // Start reading bytes into dest until a \1 is found, the buffer is full before a \1 is reached,
    // a non-hex character is read, or the timeout occurs.
    for (idx, byte) in dest.iter_mut().enumerate() {
        let second_nibble = read_hex_nibble(read_arg, &mut read_fn, timer, timeout_type)?;

        let read = if let (Some(first), Some(second)) = (first_nibble, second_nibble) {
            (first << 4) | second
        } else {
            // We've received a \1 character in the second nibble, which means we have an odd
            // number of hex digits.
            return Err(CommunicationError::RecvError);
        };

        *byte = read;

        first_nibble = read_hex_nibble(read_arg, &mut read_fn, timer, timeout_type)?;

        // We've received a \1 character in the right place.
        if first_nibble.is_none() {
            let ct = idx + 1;

            if ct < min_message_len {
                return Err(CommunicationError::RecvError);
            } else {
                return Ok(ct);
            }
        }
    }

    // If we've reached this point, it means we've reached the end of the buffer and haven't read \1
    Err(CommunicationError::RecvError)
}

/// Receives a BogoFrame, blocking until the timer has elapsed from the beginning of this
/// function call. This function mirrors
/// [`RxChannel::recv_with_timeout`](crate::communication::RxChannel::recv_with_timeout()).
/// See the documentation of that function for more details.
pub fn recv_frame_with_timeout<T, U: Timer>(
    read_arg: &mut T,
    dest: &mut [u8],
    timer: &mut U,
    read_fn: impl FnMut(&mut T) -> communication::Result<u8>,
    min_message_len: usize,
) -> communication::Result<usize> {
    recv_bogoframe(
        read_arg,
        dest,
        timer,
        read_fn,
        min_message_len,
        TimeoutType::FrameLevel,
    )
}

/// Receives a BogoFrame with the timeout provided by the specified timer.
/// This timeout resets each time a byte is read. This function mirrors
/// [`RxChannel::recv_with_data_timeout`](crate::communication::RxChannel::recv_with_data_timeout()).
/// See the documentation of that function for more details.
pub fn recv_frame_with_data_timeout<T, U: Timer>(
    read_arg: &mut T,
    dest: &mut [u8],
    timer: &mut U,
    read_fn: impl FnMut(&mut T) -> communication::Result<u8>,
    min_message_len: usize,
) -> communication::Result<usize> {
    recv_bogoframe(
        read_arg,
        dest,
        timer,
        read_fn,
        min_message_len,
        TimeoutType::ByteLevel,
    )
}

/// Sends a BogoFrame with the given [`Frame`]. This function mirrors
/// [`FramedTxChannel::frame`](super::FramedTxChannel::frame()). See the documentation of
/// that function for more details.
pub fn frame_bogoframe<const FRAME_CT: usize, T>(
    write_arg: &mut T,
    frame: Frame<FRAME_CT>,
    mut write_fn: impl FnMut(&mut T, &[u8]) -> communication::Result<()>,
    min_message_len: usize,
) -> communication::Result<()> {
    const HEX_ARRAY_LEN: usize = 32;

    if frame.len() < min_message_len {
        return Err(CommunicationError::SendError);
    }

    let mut hex_array = [0; HEX_ARRAY_LEN];

    write_fn(write_arg, &[1])?;

    for frame_piece in frame {
        for chunk in frame_piece.chunks(HEX_ARRAY_LEN / 2) {
            let to_write = &mut hex_array[..chunk.len() * 2];

            // This should never panic because the chunks should always fit in our hex array.
            hex::encode_to_slice(chunk, to_write).unwrap();

            write_fn(write_arg, to_write)?;
        }
    }

    write_fn(write_arg, &[1])?;

    Ok(())
}
