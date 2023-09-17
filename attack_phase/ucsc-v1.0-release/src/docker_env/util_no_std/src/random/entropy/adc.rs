use super::EntropySource;
use crate::RuntimePeripherals;
use bitvec::prelude::*;
use cortex_m::prelude::_embedded_hal_blocking_delay_DelayMs;
use sha3::{Digest, Sha3_256};
use tm4c123x_hal::sysctl::{control_power, reset, Domain, PowerState, RunMode};

/// Time to delay in milliseconds.
const DELAY: u32 = 1;

/// Amount to sample in bytes.
const SAMPLE_SIZE: usize = 50;

/// This entropy source gathers entropy from the LSBs of the ADC inputs.
pub(crate) struct Adc<T: EntropySource> {
    next: T,
    samples: [u8; SAMPLE_SIZE],
}

impl<T: EntropySource> EntropySource for Adc<T> {
    fn init(peripherals: &mut RuntimePeripherals) -> Self {
        // Turn it on!
        control_power(
            &peripherals.power_control,
            Domain::Adc0,
            RunMode::Run,
            PowerState::On,
        );
        reset(&peripherals.power_control, Domain::Adc0);

        let adc0 = &peripherals.adc0;
        // Turn off Sample Sequencer 3 while we configure it.
        adc0.actss.write(|w| w.asen3().clear_bit());
        // Set it to be triggered by software, this is technically the default, but why not.
        adc0.emux.write(|w| w.em3().processor());
        // We want the temperature sensor output, so we're not using any of the GPIO inputs.
        adc0.ssmux3.reset();
        // Take samples from the temperature sensor and enable interrupts.
        // We'll only be using the interrupts as a way to check if the ADC is ready.
        adc0.ssctl3
            .write(|w| w.ie0().set_bit().ts0().set_bit().end0().set_bit());
        // Turn Sample Sequencer 3 back on.
        adc0.actss.write(|w| w.asen3().set_bit());

        // At 1 ms of delay, we get around 5.301307 bits of entropy per byte if we sample 50 bytes.
        // We want 256 bits of entropy, so we need `256 bits / (5.301307 bits/byte) ≈ 386.3198264 bits` or 387 bits of raw data.
        // 397 bits / (8 bits/byte) = 48.375. We round up to 50 bytes.
        let mut samples = [0u8; SAMPLE_SIZE];
        for mut bit in samples.as_mut_bits::<Lsb0>() {
            // Start sampling.
            adc0.pssi.write(|w| w.ss3().set_bit());
            // Poll interrupt register to see if ADC is ready.
            while adc0.ris.read().inr3().bit_is_clear() {}
            let reading = adc0.ssfifo3.read().data().bits();
            // We take only the LSB, as the rest doesn't change too much.
            bit.set((reading & 0x1) == 0x1);
            // Clear interrupt by writing 1 to it.
            adc0.isc.write(|w| w.in3().set_bit());
            peripherals.delay.delay_ms(DELAY);
        }

        // Turn it off!
        reset(&peripherals.power_control, Domain::Adc0);
        control_power(
            &peripherals.power_control,
            Domain::Adc0,
            RunMode::Run,
            PowerState::Off,
        );

        Adc {
            next: T::init(peripherals),
            samples,
        }
    }

    fn add_to_hasher(&self, hasher: &mut Sha3_256) {
        hasher.update(self.samples);
        self.next.add_to_hasher(hasher);
    }
}
