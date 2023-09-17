//! The entry point for the car firmware.

#![warn(missing_docs)]
#![no_main]
#![no_std]

extern crate panic_halt;

use core::{arch::global_asm, time::Duration};
use cortex_m::interrupt;
use cortex_m_rt::entry;
use tm4c123x_hal::{CorePeripherals, Peripherals};
use ucsc_ectf_util_no_std::{
    communication::RxChannel,
    eeprom::{EepromReadWriteField, SECRET_SIZE},
    messages::Uart1Message,
    Runtime, RuntimePeripherals,
};
use zeroize::Zeroize;

mod eeprom_messages;
mod unlock;

/// The maximum size of a message that can be received/sent.
pub const MAX_MESSAGE_SIZE: usize = 1024;

// Jumps to the reset handler. This is used to allow the bootloader to execute our code.
global_asm!(
    r#"
.pushsection .text_jump, "ax"

jump_to_reset:
    b Reset

.popsection
"#
);

#[entry]
fn main() -> ! {
    // Enable interrupts because the bootloader disables them and leaves them disabled.
    // SAFETY: This is not run in an interrupt-free context, so this is safe.
    unsafe {
        interrupt::enable();
    }

    // Grab peripherals.
    let core_peripherals = CorePeripherals::take().unwrap();
    let peripherals = Peripherals::take().unwrap();
    let mut rt_peripherals = RuntimePeripherals::from((core_peripherals, peripherals));

    // Initialize runtime.
    let mut rt = Runtime::new(
        &mut rt_peripherals,
        &Default::default(),
        &Default::default(),
    );

    // Transmit and receive using unlock keys.
    let mut key_fob_encryption_key = [0; SECRET_SIZE];
    let mut car_encryption_key = [0; SECRET_SIZE];

    rt.eeprom_controller
        .read_slice(
            EepromReadWriteField::KeyFobEncryptionKey,
            &mut key_fob_encryption_key,
        )
        .expect("EEPROM read failed: key fob encryption key.");
    rt.eeprom_controller
        .read_slice(
            EepromReadWriteField::CarEncryptionKey,
            &mut car_encryption_key,
        )
        .expect("EEPROM read failed: car encryption key.");

    rt.uart1_controller
        .change_rx_key(&key_fob_encryption_key.into());
    key_fob_encryption_key.zeroize();
    rt.uart1_controller
        .change_tx_key(&car_encryption_key.into());
    car_encryption_key.zeroize();

    // Listen for unlock requests.
    loop {
        let mut receive_buffer = [0; MAX_MESSAGE_SIZE];

        // Process message if one is received on UART1.
        if let Ok(size_read) = rt.uart1_controller.recv_with_data_timeout(
            &mut receive_buffer,
            &mut rt.hib_controller.create_timer(Duration::from_secs(1000)),
        ) {
            let msg = match postcard::from_bytes::<Uart1Message>(&receive_buffer[..size_read]) {
                Ok(msg) => msg,
                Err(_) => continue,
            };

            unlock::process_msg(&mut rt, &msg);
        }
    }
}
