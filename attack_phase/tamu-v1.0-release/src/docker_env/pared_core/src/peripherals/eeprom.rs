use rand_chacha::rand_core::SeedableRng;
use cortex_m::asm::delay;
use crate::crypto::{oneshot_hash, verify_hash};
use crate::error::{Error, Result};
use eeprom_layout::{Hashed, Primitive};
use rand_chacha::ChaChaRng;
use tm4c123x_hal::{
    sysctl::{control_power, reset, Domain, PowerState, RunMode, Sysctl},
    tm4c123x::EEPROM,
};

pub struct Eeprom(EEPROM);

impl Eeprom {
    #[inline(always)]
    fn wait(eeprom: &EEPROM) {
        while eeprom.eedone.read().working().bit_is_set() {}
    }
    #[inline(always)]
    fn check_errors(eeprom: &EEPROM) {
        let status = eeprom.eesupp.read();

        if status.pretry().bit_is_set() || status.eretry().bit_is_set() {
            panic!("initialization should never fail");
        }
    }
    pub fn init(eeprom: EEPROM, sysctl: &mut Sysctl) -> Self {
        control_power(
            &sysctl.power_control,
            Domain::Eeprom,
            RunMode::Run,
            PowerState::On,
        );

        delay(6);

        Self::wait(&eeprom);
        Self::check_errors(&eeprom);

        reset(&sysctl.power_control, Domain::Eeprom);

        delay(2);

        Self::wait(&eeprom);
        Self::check_errors(&eeprom);

        Eeprom(eeprom)
    }
    const fn offset_from_addr(addr: usize) -> u32 {
        (addr as u32 >> 2) & 0b0000_1111
    }
    const fn block_from_addr(addr: usize) -> u32 {
        addr as u32 >> 6
    }
    pub fn read(&self, buf: &mut [u32], addr: usize) -> Result<()> {
        if buf.is_empty() {
            return Err(Error::EepromRead);
        }

        let last = buf.len() - 1;
        let block = Self::block_from_addr(addr);
        let offset = Self::offset_from_addr(addr);
        self.0.eeblock.write(|w| unsafe { w.bits(block) });
        self.0.eeoffset.write(|w| unsafe { w.bits(offset) });

        for (i, slot) in buf.iter_mut().enumerate() {
            *slot = self.0.eerdwrinc.read().bits();

            // Only modify EEBLOCK if we're not on the last iteration.
            if i != last && self.0.eeoffset.read().bits() == 0 {
                self.0
                    .eeblock
                    .modify(|r, w| unsafe { w.bits(r.bits() + 1) });
            }
        }

        Ok(())
    }
    pub fn write(&self, data: &[u32], addr: usize) -> Result<()> {
        if data.is_empty() {
            return Err(Error::EepromWrite);
        }

        // Make sure the EEPROM is idle before we start.
        Self::wait(&self.0);

        let last = data.len() - 1;
        let block = Self::block_from_addr(addr);
        let offset = Self::offset_from_addr(addr);
        self.0.eeblock.write(|w| unsafe { w.bits(block) });
        self.0.eeoffset.write(|w| unsafe { w.bits(offset) });

        for (i, &word) in data.iter().enumerate() {
            self.0.eerdwrinc.write(|w| unsafe { w.bits(word) });

            delay(10);

            Self::wait(&self.0);

            if i != last && self.0.eeoffset.read().bits() == 0 {
                self.0
                    .eeblock
                    .modify(|r, w| unsafe { w.bits(r.bits() + 1) });
            }
        }

        Ok(())
    }
    pub fn load<T: Primitive>(&self) -> Result<T> {
        let mut t = T::zeroed();
        self.read(t.as_words_mut(), T::OFFSET)?;
        Ok(t)
    }
    pub fn store<T: Primitive>(&self, t: &T) -> Result<()> {
        self.write(t.as_words(), T::OFFSET)
    }
    pub fn store_hashed<T: Primitive>(&self, t: T) -> Result<()> {
        let h = Hashed::new(t);
        self.store(&h)
    }
    pub fn load_hashed<T: Primitive>(&self, r: &mut ChaChaRng) -> Result<T> {
        let h = self.load::<Hashed<T>>()?;
        verify_hash(h.data.as_bytes(), &h.hash, r).map(move |_| h.data)
    }
    fn increment(xs: &mut [u8]) {
        let mut add = 1;
        for b in xs.iter_mut() {
            let (res, carry) = b.overflowing_add(add);
            *b = res;
            add = carry as u8;
        }
    }
    pub fn load_seed<T: Primitive>(&self) -> Result<ChaChaRng> {
        let mut seed = self.load::<Hashed<T>>()?;
        let new_hash = oneshot_hash(&seed.data.as_bytes());
        if seed.hash != new_hash {
            return Err(Error::InvalidHash);
        }
        Self::increment(&mut seed.data.as_bytes_mut());
        seed.hash = oneshot_hash(&seed.data.as_bytes());
        self.store(&seed)?;
        let mut actual_seed = [0; 32];
        actual_seed.copy_from_slice(seed.data.as_bytes());
        Ok(ChaChaRng::from_seed(actual_seed))
    }
}
