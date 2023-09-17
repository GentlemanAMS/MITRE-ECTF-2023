#![no_std]
#![no_main]

mod crypto;
mod handlers;

use core::arch::asm;
use cortex_m::asm::delay;
use cortex_m_rt::{entry, pre_init};
use eeprom_layout::fob::{FobSeed, TextHash, Timeout};
#[cfg(feature = "panic-halt")]
use panic_halt as _;
use pared_core::error::{Error, Result};
use pared_core::hash_text_section;
use pared_core::peripherals::uart::{FRAME_OK, FRAME_BAD};
use pared_core::peripherals::Peripherals;
use rand_chacha::ChaChaRng;

pub const NO_COMMAND: u8 = 0xfe;

#[pre_init]
unsafe fn reset_sp() {
    let stack_top = 0x2000_4000_u32;
    asm!("msr MSP, {stack_top}", stack_top = in(reg) stack_top);
}

#[entry]
fn entry() -> ! {
    let _ = main();
    panic!("Taking an L");
}

#[inline(always)]
pub fn main() -> Result<()> {
    let mut p = Peripherals::init();
    if hash_text_section() != p.eeprom.load::<TextHash>()?.0 {
        return Err(Error::InvalidHash);
    }

    let mut rng = p.eeprom.load_seed::<FobSeed>()?;
    p.uart_ht.flush();
    p.uart_board.flush();
    p.uart_ht.write_all(b"Started");
    loop {
        let timeout = p.eeprom.load_hashed::<Timeout>(&mut rng)?.0;
        if timeout > 0 {
            delay(timeout);
            p.eeprom.store_hashed::<Timeout>(Timeout(0))?;
        }

        let status = match run_cmd(&mut p, &mut rng) {
            Ok(o) => o,
            Err(_) => FRAME_BAD,
        };

        if status != NO_COMMAND {
            p.uart_ht.flush();
            p.uart_ht.write_u8(status);
        }
    }
}

pub fn run_cmd(p: &mut Peripherals, r: &mut ChaChaRng) -> Result<u8> {
    if p.button.is_pressed() {
        match handlers::unlock(p, r) {
            Ok(_) => return Ok(b'U'),
            Err(e) => return Err(e),
        }
    }
    match p.uart_ht.nonblocking_read_u8_opt() {
        Some(b'E') => handlers::enable_feature(p, r)?,
        Some(b'P') => {p.uart_ht.write_all(b"P");p.uart_board.flush(); handlers::pairer(p, r)?},
        Some(b'U') => {p.uart_board.flush(); handlers::pairee(p, r)?},
        Some(b'T') => {p.uart_ht.write_all(b"AAAA");},
        Some(_) => return Err(Error::InvalidCmd),
        None => return Ok(NO_COMMAND),
    };
    Ok(FRAME_OK)
}
