//! Provides the ability to read and write data over some communication channel.
use crate::utils::timing::Timeout;

/// Errors that can occur in I/O operations.
#[derive(Debug)]
pub enum Error {
    /// Occurs when an invalid acknowledgement byte is received
    /// while transferring a large message.
    InvalidAcknowledgement,

    /// Occurs when a time-limited read fails to complete on time.
    TimedOut,
}

impl Error {
    pub fn get_status_code(&self) -> u32 {
        match *self {
            Self::InvalidAcknowledgement => 0xDEAC,
            Self::TimedOut => 0xDEAD,
        }
    }
}

pub type Result<T> = core::result::Result<T, Error>;

/// A channel that can be used to send and receive data.
/// Currently, UART is the only supported channel, although a dummy implementation exists for tests.
pub trait IO {
    /// Checks whether data is available to read from the channel.
    fn data_avail(&self) -> bool;

    /// Writes a byte to the channel.
    fn write_byte(&self, byte: u8);

    /// Reads a byte from the channel.
    fn read_byte(&self) -> u8;
    
    /// Attempts to read a byte until one is retrieved or a timeout expires.
    /// The `timeout` is responsible for checking timeout status.
    fn read_byte_timeout<'a, 'b: 'a>(&'a self, timeout: &'b dyn Timeout) -> Result<u8>;

    /// Reads all available bytes from the channel.
    fn drain(&self) {
        while self.data_avail() {
            let _ = self.read_byte();
        }
    }

    /// Writes multiple bytes to the channel, handling acknowledgements.
    /// 
    /// # Panics
    /// The default implementation of this function will panic 
    /// if an invalid acknowledgement response is received.
    fn write<T, Item>(&self, data: &T) -> Result<()>
    where
        T: IntoIterator<Item = Item> + Copy,
        Item: Into<u8>,
    {
        let mut count = 0;
        for d in *data {
            let val: u8 = d.into();
            self.write_byte(val);
            count += 1;

            if count >= 15 {
                let r = self.read_byte();

                if r != b'Z' {
                    return Err(Error::InvalidAcknowledgement);
                }

                count = 0;
            }
        }

        Ok(())
    }

    /// Reads multiple bytes from the channel, handling acknowledgements.
    fn read(&self, buf: &mut [u8]) {
        let mut count = 0;

        // Read two characters since they are all double sent
        // If they're the same, great just go with it
        // If they're different, this should ONLY happen when one is 00 and one is not
        // When this happens, read an extra byte and take that value
        for b in buf {
            *b = self.read_byte();
            count += 1;

            if count >= 15 {
                self.write_byte(b'Z');
                count = 0;
            }
        }
    }

    /// Attempts to read multiple bytes from the channel, failing if a timeout expires.
    fn read_with_timeout<'a, T: Timeout + 'a>(&'a self, buf: &mut [u8], timeout: T) -> Result<()> {
        let mut count = 0;

        // Read two characters since they are all double sent
        // If they're the same, great just go with it
        // If they're different, this should ONLY happen when one is 00 and one is not
        // When this happens, read an extra byte and take that value
        for b in buf {
            *b = self.read_byte_timeout(&timeout)?;
            count += 1;

            if count >= 15 {
                self.write_byte(b'Z');
                count = 0;
            }
        }

        Ok(())
    }
}
