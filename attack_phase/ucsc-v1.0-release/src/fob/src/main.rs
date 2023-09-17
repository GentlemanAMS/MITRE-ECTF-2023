//! The entry point for the key fob firmware.

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
    eeprom::{EepromReadWriteField, BYTE_FIELD_SIZE},
    messages::Uart0Message,
    Runtime, RuntimePeripherals,
};

mod features;
mod pairing;
mod unlock;

/// The maximum size of a message that can be received/sent.
pub const MAX_MESSAGE_SIZE: usize = 1024;

const UNPAIRED: u8 = 0;
const MS_TO_WAIT_FOR_MSG: u64 = 5;

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

    // Get pairing status.
    let mut pairing_byte = [0; BYTE_FIELD_SIZE];

    rt.eeprom_controller
        .read_slice(EepromReadWriteField::PairingByte, &mut pairing_byte)
        .unwrap();

    // Listen for pairing requests from paired key fob if unpaired.
    if pairing_byte[0] == UNPAIRED {
        pairing::unpaired_listen_and_pair(&mut rt);
    }

    // Listen for pairing requests from host, features, and button presses.
    loop {
        let mut receive_buffer = [0; MAX_MESSAGE_SIZE];

        // Process message if one is received on UART0.
        if let Ok(size_read) = rt.uart0_controller.recv_with_data_timeout(
            &mut receive_buffer,
            &mut rt
                .hib_controller
                .create_timer(Duration::from_millis(MS_TO_WAIT_FOR_MSG)),
        ) {
            let msg = match postcard::from_bytes::<Uart0Message>(&receive_buffer[..size_read]) {
                Ok(msg) => msg,
                Err(_) => continue,
            };

            pairing::paired_process_msg(&mut rt, &msg);
            features::paired_process_msg(&mut rt, &msg);
        }

        // Process SW1 button press.
        if rt.sw1_button_controller.poll_for_activation() {
            unlock::process_button_press(&mut rt);
            rt.sw1_button_controller.clear_activation();
        }
    }
}
