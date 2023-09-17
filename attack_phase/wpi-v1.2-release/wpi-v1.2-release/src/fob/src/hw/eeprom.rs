//! EEPROM reading and writing support.
//! Addresses of various EEPROM variables are provided for convenience.
pub const SYM_KEY_EEPROM_ADDR: u32 = 0x00; // 32 bytes
pub const SEED_EEPROM_ADDR: u32 = 0x20; // 32 bytes
pub const NONCE_ID_EEPROM_ADDR: u32 = 0x40; // 24 bytes
pub const UNLOCK_PASSWD_EEPROM_ADDR: u32 = 0x58; // 32 bytes

pub const CAR_ID_EEPROM_ADDR: u32 = 0x78; // 4 bytes
pub const PAIRED_STATUS_EEPROM_ADDR: u32 = 0x84; // 4 bytes (actually 1 byte)

pub const NUM_FEATURES_EEPROM_ADDR: u32 = 0x88; // 4 bytes (actually 1 byte)
pub const FEATURE_1_EEPROM_ADDR: u32 = 0x8C; // 84 bytes
pub const FEATURE_2_EEPROM_ADDR: u32 = 0xE0; // 84 bytes
pub const FEATURE_3_EEPROM_ADDR: u32 = 0x134; // 84 bytes

pub const VERIFYING_KEY_EEPROM_ADDR: u32 = 0x200;    // 32 bytes

pub const PIN_DERIVED_KEY_SALT_ADDR: u32 = 0x280;
pub const FOB_ID_ADDR: u32 = 0x2A0;
pub const PIN_PROTECTED_PAYLOAD_NONCE_ADDR: u32 = 0x2C0;
pub const PIN_PROTECTED_PAYLOAD_ADDR: u32 = 0x300;

pub const PW_DERIVED_KEY_SALT_ADDR: u32 = 0x400;
pub const PW_PROTECTED_PAYLOAD_NONCE_ADDR: u32 = 0x420;
pub const PW_PROTECTED_PAYLOAD_ADDR: u32 = 0x440;

pub const FEATURE_MSG_1_EEPROM_ADDR: u32 = 0x780;
pub const FEATURE_MSG_2_EEPROM_ADDR: u32 = 0x740;
pub const FEATURE_MSG_3_EEPROM_ADDR: u32 = 0x700;
pub const UNLOCK_MESSAGE_EEPROM_ADDR: u32 = 0x7C0;

use core::{marker::PhantomData, mem::zeroed};

use crate::tivaware::{
    EEPROMInit, EEPROMProgram, EEPROMRead, SysCtlPeripheralEnable, EEPROM_INIT_OK,
    SYSCTL_PERIPH_EEPROM0,
};

// Not Test (Hardware Functions)

/// Initializes the EEPROM peripheral.
#[allow(clippy::panic)]
pub fn eeprom_init() {
    unsafe {
        SysCtlPeripheralEnable(SYSCTL_PERIPH_EEPROM0);

        if EEPROMInit() != EEPROM_INIT_OK {
            // PANIC JUSTIFICATION: 
            // This panic exists specifically to detect hardware issues, whether
            // they're caused by intentional interference or simply by faulty components.
            // This particular panic is triggered by something that should absolutely never happen, 
            // and if it does, then all bets are off and there is no clear path to recovery.
            panic!("EEPROM failed to init");
        }
    }
}

/// Reads bytes from the EEPROM
#[cfg(not(test))]
unsafe fn eeprom_read_bytes(dest: *mut u8, addr: usize, cnt: usize) {
    assert_eq!(addr % 4, 0);
    assert_eq!(cnt % 4, 0);

    EEPROMRead(dest as *mut u32, addr as u32, cnt as u32);
}

/// Writes bytes to the EEPROM
#[cfg(not(test))]
#[allow(clippy::panic)]
unsafe fn eeprom_write_bytes(data: *const u8, addr: usize, cnt: usize) {
    assert_eq!(addr % 4, 0);
    assert_eq!(cnt % 4, 0);        
    
    if EEPROMProgram(data as *const u32, addr as u32, cnt as u32) != 0 {
        // PANIC JUSTIFICATION: 
        // This panic exists specifically to detect hardware issues, whether
        // they're caused by intentional interference or simply by faulty components.
        // This particular panic is triggered by something that should absolutely never happen, 
        // and if it does, then all bets are off and there is no clear path to recovery.
        panic!("EEPROM write failed");
    }
}

// Test (Mock EEPROM)

#[cfg(test)]
unsafe fn eeprom_read_bytes(d: *mut u8, addr: usize, cnt: usize) {
    use core::ops::DerefMut;

    use crate::test::EEPROM_DUMMY;

    let mut binding = EEPROM_DUMMY.lock().unwrap();
    let inner = binding.deref_mut();

    unsafe {
        for i in 0..cnt {
            *d.add(i) = inner[addr + i];
        }
    }
}

#[cfg(test)]
unsafe fn eeprom_write_bytes(d: *const u8, addr: usize, cnt: usize) {
    use core::ops::DerefMut;

    use crate::test::EEPROM_DUMMY;

    let mut binding = EEPROM_DUMMY.lock().unwrap();
    let inner = binding.deref_mut();

    unsafe {
        for i in 0..cnt {
            inner[addr + i] = *d.add(i);
        }
    }
}

#[cfg(test)]
pub fn eeprom_scope<T>(scope_fn: impl FnOnce() -> T) -> T {
    use crate::test::EEPROM_DUMMY_SCOPE;

    let _binding = EEPROM_DUMMY_SCOPE.lock().unwrap();
    (scope_fn)()
}

trait IsEEPROMCompatible {
    const RESULT: ();
}

impl<T: Sized> IsEEPROMCompatible for T {
    const RESULT: () = {
        if core::mem::size_of::<T>() % 4 != 0 {
            panic!("the size of this type is not a multiple of the EEPROM word size (4 bytes)");
        }
    };
}

trait IsValidEEPROMAddress {
    const RESULT: ();
}

struct IsValidEEPROMAddressImpl<const ADDRESS: u32>;

impl<const ADDRESS: u32> IsValidEEPROMAddress for IsValidEEPROMAddressImpl<ADDRESS> {
    const RESULT: () = {
        if ADDRESS % 4 != 0 {
            panic!("the requested address is not a multiple of the EEPROM word size (4 bytes)");
        } else if ADDRESS > (0x800 - 4) {
            panic!("the requested address is beyond the maximum EEPROM address (0x7FC)");
        }
    };
}

/// An EEPROM location that can be read from and written to.
pub struct EEPROMVar<Inner>
where
    Inner: Sized + PartialEq,
{
    _addr: u32,
    _inner: PhantomData<Inner>,
}

impl<Inner> EEPROMVar<Inner>
where
    Inner: Sized + PartialEq,
{
    /// Creates an [`EEPROMVar`].
    /// 
    /// # Safety
    /// The Tiva EEPROM module does not allow accesses (read/write) that are not 
    /// aligned to 4 bytes. Accordingly, we block at compile-time the construction 
    /// of an [`EEPROMVar`] that would violate this rule.
    pub fn new<const ADDRESS: u32>() -> Self {
        // Safety check #1: ensure the data type is compatible with
        // being read from/written to EEPROM, i.e., its size is
        // a multiple of 4 bytes.
        let _ = <Inner as IsEEPROMCompatible>::RESULT;

        // Safety check #2: ensure the address is valid, i.e., it is
        // a multiple of 4 bytes.
        let _ = <IsValidEEPROMAddressImpl<ADDRESS> as IsValidEEPROMAddress>::RESULT;

        Self {
            _addr: ADDRESS,
            _inner: PhantomData,
        }
    }

    /// Reads the value stored at the EEPROM location.    
    pub fn read(&self) -> Inner {
        unsafe {
            let mut ret: Inner = zeroed();

            eeprom_read_bytes(
                &mut ret as *mut Inner as *mut u8,
                self._addr as usize,
                core::mem::size_of::<Inner>(),
            );

            ret
        }
    }

    /// Writes a new value to the EEPROM location.
    /// 
    /// # Safety
    /// While this function uses unsafe code, it is in fact perfectly safe.
    /// No out-of-bounds data access can occur as long as fundamental rules
    /// of the Rust programming language haven't already been broken.
    /// 
    /// As far as we know, that's not something that can just happen out of the blue,
    /// so this function is safe.
    /// 
    /// # Panics
    /// This function performs integrity checking to ensure that data was not corrupted
    /// during the write. If the integrity check fails (which has never been observed),
    /// the function will panic.
    #[allow(clippy::panic)]
    pub fn write(&mut self, v: &Inner) {
        unsafe {
            eeprom_write_bytes(
                v as *const Inner as *const u8,
                self._addr as usize,
                core::mem::size_of::<Inner>(),
            );
        }

        // PANIC JUSTIFICATION: 
        // This panic exists specifically to detect hardware issues, whether
        // they're caused by intentional interference or simply by faulty components.
        // This particular panic is triggered by something that should absolutely never happen, 
        // and if it does, then all bets are off and there is no clear path to recovery. 
        if &self.read() != v {
            panic!("EEPROM post-write integrity check failed")
        }
    }
}

#[cfg(test)]
mod tests {
    use core::marker::PhantomData;

    use super::{eeprom_scope, EEPROMVar};

    #[derive(PartialEq, Debug, Clone, Copy)]
    struct TestStruct1 {
        my_u8: u8,
        my_u32: u32,
    }

    #[derive(PartialEq, Debug, Clone, Copy)]
    struct TestStruct2 {
        my_u8: u8,
        my_u32: u32,
        my_nested: TestStruct1,
    }

    #[test]
    fn write_at() {
        eeprom_scope(|| {
            let mut key = EEPROMVar::<TestStruct2>::new::<0x0>();

            let s = TestStruct2 {
                my_u8: 1,
                my_u32: 44,
                my_nested: TestStruct1 {
                    my_u8: 52,
                    my_u32: 212,
                },
            };
            let s_c = s.clone();

            key.write(&s);
            assert_eq!(key.read(), s_c);
        });
    }
}
