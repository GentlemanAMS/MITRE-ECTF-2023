use super::EntropySource;
use crate::RuntimePeripherals;
use bitvec::prelude::*;
use sha3::{digest::Update, Sha3_256};
use tm4c123x_hal::sysctl::{self, Domain, PowerState, RunMode};

/// Number of subseconds to count for clock drift.
const SUBSECONDS_TO_COUNT: usize = 16;

/// Number of bytes to gather for clock drift.
// Each run takes ~1 / (32768/SUBSECONDS_TO_COUNT) seconds. Take 1/2 seconds worth of reads. Each run
// yields 1 bit. 8 bits per byte.
const CLOCK_DRIFT_ENTROPY_SIZE: usize = 32768 / SUBSECONDS_TO_COUNT / 2 / 8;

/// This entropy source gathers entropy from drift between clocks on the board.
pub(crate) struct ClockDrift<T: EntropySource> {
    next: T,
    entropy_pool: [u8; CLOCK_DRIFT_ENTROPY_SIZE],
}

impl<T: EntropySource> EntropySource for ClockDrift<T> {
    fn init(peripherals: &mut RuntimePeripherals) -> Self {
        // Enable hibernation module. This is enabled by default, but we enable it here just in case.
        sysctl::control_power(
            &peripherals.power_control,
            Domain::Hibernation,
            RunMode::Run,
            PowerState::On,
        );

        // Reset hibernation module for good measure.
        sysctl::reset(&peripherals.power_control, Domain::Hibernation);

        // Initialize hibernation clock.
        peripherals.hib.ctl.write(|w| {
            // Use low-frequency oscillator and enable clock.
            w.oscbyp().clear_bit().clk32en().set_bit()
        });

        // Wait for hibernation module to be ready.
        while peripherals.hib.ctl.read().wrc().bit_is_clear() {}

        // Initialize internal entropy pool.
        let mut entropy_pool: [u8; CLOCK_DRIFT_ENTROPY_SIZE] = [0; CLOCK_DRIFT_ENTROPY_SIZE];

        for mut bit in entropy_pool.as_mut_bits::<Lsb0>() {
            // Disable RTC.
            // SAFETY: Writing to this register is safe because it is data-race free. This guarantee
            // comes from the fact that the peripherals are borrowed mutably.
            peripherals
                .hib
                .ctl
                .modify(|r, w| unsafe { w.bits(r.bits()).rtcen().clear_bit() });

            // Wait for hibernation module to be ready.
            while peripherals.hib.ctl.read().wrc().bit_is_clear() {}

            // Set RTC to 0.
            // SAFETY: Writing to this register is safe because it is data-race free. This guarantee
            // comes from the fact that the peripherals are borrowed mutably.
            peripherals.hib.rtcld.write(|w| unsafe { w.bits(0) });

            // Wait for hibernation module to be ready.
            while peripherals.hib.ctl.read().wrc().bit_is_clear() {}

            // Enable RTC.
            // SAFETY: Writing to this register is safe because it is data-race free. This guarantee
            // comes from the fact that the peripherals are borrowed mutably.
            peripherals
                .hib
                .ctl
                .modify(|r, w| unsafe { w.bits(r.bits()).rtcen().set_bit() });

            // Wait for hibernation module to be ready.
            while peripherals.hib.ctl.read().wrc().bit_is_clear() {}

            // Wait for RTC to reach SUBSECONDS_TO_COUNT subseconds and count.
            let mut counter: u32 = 0;

            while SUBSECONDS_TO_COUNT > peripherals.hib.rtcss.read().rtcssc().bits().into() {
                counter += 1;
            }

            // Set bit to 1 if counter LSB is 1.
            bit.set((counter & 1) == 1);
        }

        // Reset hibernation module to disable the hibernation clock.
        sysctl::reset(&peripherals.power_control, Domain::Hibernation);

        ClockDrift {
            next: T::init(peripherals),
            entropy_pool,
        }
    }

    fn add_to_hasher(&self, hasher: &mut Sha3_256) {
        hasher.update(&self.entropy_pool);
        self.next.add_to_hasher(hasher);
    }
}
