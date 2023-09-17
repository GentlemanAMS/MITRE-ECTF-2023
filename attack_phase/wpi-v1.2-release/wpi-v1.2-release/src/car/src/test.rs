use alloc::collections::VecDeque;
use core::marker::PhantomData;
use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::cell::RefCell;
use std::sync::Mutex;

extern crate alloc;

use crate::comms::{error::Error, io::IO, io::Result};
use crate::comms::noncegenerator::NonceGenerator;
use crate::comms::packet::PacketIO;
use lazy_static::lazy_static;

use super::*;

// Dummy IO for UART-based Tests

pub struct DummyIO {
    backing: RefCell<VecDeque<u8>>,
}

impl DummyIO {
    pub fn new() -> DummyIO {
        DummyIO {
            backing: RefCell::new(VecDeque::new()),
        }
    }
}

impl IO for DummyIO {
    fn data_avail(&self) -> bool {
        !self.backing.borrow().is_empty()
    }

    fn write_byte(&self, byte: u8) {
        self.backing.borrow_mut().push_front(byte);
    }

    fn read_byte(&self) -> u8 {
        self.backing.borrow_mut().pop_back().unwrap()
    }

    fn read_byte_timeout<'a, 'b: 'a>(&self, time_keeper: &'b dyn utils::timing::Timeout) -> Result<u8> {
        Ok(self.read_byte())
    }

    fn write<T, Item>(&self, data: &T) -> Result<()>
    where
        T: IntoIterator<Item = Item> + Copy,
        Item: Into<u8>,
    {
        for b in *data {
            self.write_byte(b.into());
        }
        Ok(())
    }

    fn read(&self, buf: &mut [u8]) {
        for b in buf {
            *b = self.read_byte();
        }
    }
}

impl PacketIO for DummyIO {}

// Dummy EEPROM R/W

lazy_static! {
    pub static ref EEPROM_DUMMY: Mutex<[u8; 1400]> = Mutex::new([0u8; 1400]);
    pub static ref EEPROM_DUMMY_SCOPE: Mutex<()> = Mutex::new(());
}
