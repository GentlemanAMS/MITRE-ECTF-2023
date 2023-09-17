use crate::error::{Error, Result};
use nb::block;
use tm4c123x_hal::gpio::{
    gpioa::{PA0, PA1},
    gpiob::{PB0, PB1},
    AlternateFunction, PushPull, AF1,
};
use tm4c123x_hal::prelude::*;
use tm4c123x_hal::serial::{Serial, UART0, UART1};

pub const FRAME_BAD: u8 = 0x2c;
pub const FRAME_OK: u8 = 0xf0;

pub struct Uart0(
    pub  Serial<
        UART0,
        PA1<AlternateFunction<AF1, PushPull>>,
        PA0<AlternateFunction<AF1, PushPull>>,
        (),
        (),
    >,
);

pub struct Uart1(
    pub  Serial<
        UART1,
        PB1<AlternateFunction<AF1, PushPull>>,
        PB0<AlternateFunction<AF1, PushPull>>,
        (),
        (),
    >,
);

macro_rules! impl_uart {
    ($t:ty) => {
        impl $t {
            pub fn write_u8(&mut self, b: u8) {
                block!(self.0.write(b)).unwrap();
            }

            pub fn ready_write_u8(&mut self, b: u8) -> Result<()> {
                self.recv_ok()?;
                self.write_u8(b);
                Ok(())
            }

            pub fn write_all(&mut self, bs: &[u8]) {
                self.0.write_all(bs);
            }

            pub fn ready_write_all(&mut self, bs: &[u8]) -> Result<()> {
                self.recv_ok()?;
                self.write_all(bs);
                Ok(())
            }
            
            pub fn blocking_read_u8(&mut self) -> u8 {
                block!(self.0.read()).unwrap()
            }
            pub fn nonblocking_read_u8_opt(&mut self) -> Option<u8> {
                self.0.read().ok()
            }
            pub fn nonblocking_read_u8(&mut self) -> Result<u8> {
                const THRESHOLD: u32 = 20_000_000;
                let mut count = 0u32;
                loop {
                    match self.0.read() {
                        Ok(b) => return Ok(b),
                        Err(nb::Error::WouldBlock) => {
                            count += 1;
                            if count > THRESHOLD {
                                return Err(Error::UartTimeout);
                            }
                        }
                        Err(nb::Error::Other(_)) => {
                            unreachable!();
                        }
                    }
                }
            }
            pub fn ready_blocking_read_u8(&mut self) -> u8 {
                self.write_u8(FRAME_OK);
                self.blocking_read_u8()
            }
            pub fn ready_nonblocking_read_u8(&mut self) -> Result<u8> {
                self.write_u8(FRAME_OK);
                self.nonblocking_read_u8()
            }
            pub fn ready_nonblocking_read_be_u32(&mut self) -> Result<u32> {
                self.write_u8(FRAME_OK);
                Ok(u32::from_be_bytes([
                    self.nonblocking_read_u8()?,
                    self.nonblocking_read_u8()?,
                    self.nonblocking_read_u8()?,
                    self.nonblocking_read_u8()?,
                ]))
            }
            pub fn ready_nonblocking_read_exact(&mut self, buf: &mut [u8]) -> Result<()> {
                self.write_u8(FRAME_OK);
                for b in buf.iter_mut() {
                    *b = self.nonblocking_read_u8()?;
                }
                Ok(())
            }
            pub fn ready_nonblocking_read_arr<const N: usize>(&mut self) -> Result<[u8; N]> {
                let mut arr = [0u8; N];
                self.ready_nonblocking_read_exact(&mut arr)?;
                Ok(arr)
            }
            pub fn flush(&mut self) {
                while self.0.read().is_ok() {}
            }
            pub fn recv_ok(&mut self) -> Result<()> {
                if self.nonblocking_read_u8()? == FRAME_OK {
                    Ok(())
                } else {
                    Err(Error::InvalidReady)
                }
            }
        }
    };
}

impl_uart!(Uart0);
impl_uart!(Uart1);
