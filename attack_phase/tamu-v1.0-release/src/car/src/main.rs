#![no_std]
#![no_main]
extern crate static_assertions as sa;
use blake2::{Blake2s256, Digest};
use pared_core::peripherals::uart::FRAME_BAD;
use core::arch::asm;
use cortex_m_rt::{entry, pre_init};
use eeprom_layout::car::*;
use eeprom_layout::Primitive;
use p256::ecdsa::signature::Verifier;
use panic_halt as _;
use pared_core::crypto::{jitter, Challenge, FeaturePackage};
use pared_core::error::Error;
use pared_core::error::Result;
use pared_core::hash_text_section;
use pared_core::peripherals::uart::FRAME_OK;
use pared_core::peripherals::Peripherals;
use rand_chacha::ChaChaRng;

#[pre_init]
unsafe fn reset_sp() {
    let stack_top = 0x2000_4000_u32;
    asm!("msr MSP, {stack_top}", stack_top = in(reg) stack_top);
}

#[entry]
fn entry() -> ! {
    let _ = main();
    panic!("F, something went wrong");
}

pub fn main() -> Result<()> {
    let mut p = Peripherals::init();
    if hash_text_section() != p.eeprom.load::<TextHash>()?.0 {
        return Err(Error::InvalidHash);
    }

    let mut rng = p.eeprom.load_seed::<CarSeed>()?;

    loop {
        match p.uart_board.blocking_read_u8() {
            b'U' => {
                let status = if let Err(_) = unlock(&mut p, &mut rng) {
                    FRAME_BAD
                } else {
                    FRAME_OK
                };
                p.uart_ht.flush();
                p.uart_ht.write_u8(status);
            }
            b => {
                p.uart_ht.write_u8(b);    
            },
        }
    }
}

#[inline(always)]
fn auth(p: &mut Peripherals, r: &mut ChaChaRng) -> Result<FeaturePackage> {
    let signing_key = p.eeprom.load_hashed::<CarAuthPrivKey>(r)?.0.load();
    let verifying_key = p.eeprom.load_hashed::<PairedPubKey>(r)?.0.load();

    let chall = Challenge::new(r, &signing_key);
    p.uart_board.ready_write_all(chall.as_bytes())?;

    let mut res = FeaturePackage::zeroed();
    p.uart_board
        .ready_nonblocking_read_exact(res.as_bytes_mut())?;

    jitter(r);
    verifying_key.verify(&res.hash, &res.signature)?;

    let h = {
        let mut hasher = Blake2s256::new();
        hasher.update(&res.enabled_features);
        hasher.update(chall.nonce);
        hasher.finalize()
    };
    if h != res.hash {
        return Err(Error::InvalidHash);
    }
    Ok(res)
}

fn unlock(p: &mut Peripherals, r: &mut ChaChaRng) -> Result<()> {
    let res = auth(p, r)?;

    p.uart_ht.write_u8(1);
    p.uart_ht.write_all(&p.eeprom.load::<Unlock>()?.0);

    if res.enabled_features[0] == 1 {
        p.uart_ht.write_u8(1);
        p.uart_ht.write_all(&p.eeprom.load::<Feature1>()?.0);
    }
    if res.enabled_features[1] == 1 {
        p.uart_ht.write_u8(1);
        p.uart_ht.write_all(&p.eeprom.load::<Feature2>()?.0);
    }
    if res.enabled_features[2] == 1 {
        p.uart_ht.write_u8(1);
        p.uart_ht.write_all(&p.eeprom.load::<Feature3>()?.0);
    }

    Ok(())
}
