use color_eyre::{eyre::ensure, Result};
use std::io::{BufReader, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

pub const FRAME_BAD: u8 = 0x2c;
pub const FRAME_OK: u8 = 0xf0;

pub struct Socket {
    inner: BufReader<TcpStream>,
}

impl Socket {
    pub fn connect(port: u16, secs: u64) -> Result<Self> {
        let stream = TcpStream::connect(("ectf-net", port))?;
        stream.set_read_timeout(Some(Duration::from_secs(secs)))?;

        Ok(Self {
            inner: BufReader::new(stream),
        })
    }

    pub fn recv(&mut self, n: usize) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; n];
        self.inner.read_exact(&mut buf)?;

        Ok(buf)
    }

    pub fn recv_byte(&mut self) -> Result<u8> {
        let mut byte = 0;
        self.inner.read_exact(std::array::from_mut(&mut byte))?;
        Ok(byte)
    }

    pub fn send(&mut self, msg: &[u8]) -> Result<()> {
        Ok(self.inner.get_mut().write_all(msg)?)
    }

    pub fn recv_ok(&mut self) -> Result<()> {
        let response = self.recv_byte()?;
        ensure!(response == FRAME_OK, "ERROR: responded with {response}");
        Ok(())
    }

    pub fn ready_send(&mut self, msg: &[u8]) -> Result<()> {
        self.recv_ok()?;
        self.send(msg)?;
        Ok(())
    }
}
