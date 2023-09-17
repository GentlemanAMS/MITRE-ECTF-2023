//! This module contains an interface to use the hibernation clock.

use crate::{timer::HibTimer, HibPool};
use core::time::Duration;
use heapless::Arc;
use tm4c123x_hal::sysctl::{self, Domain, PowerControl, PowerState, RunMode};

/// The hibernation controller.
#[derive(Clone)]
pub struct HibController {
    hib: Arc<HibPool>,
}

impl HibController {
    /// Creates a new hibernation controller.
    pub(crate) fn new(hib: Arc<HibPool>, power_control: &PowerControl) -> Self {
        // Enable hibernation module. This is enabled by default, but we enable it here just in case.
        sysctl::control_power(
            power_control,
            Domain::Hibernation,
            RunMode::Run,
            PowerState::On,
        );

        // Reset hibernation module for good measure.
        sysctl::reset(power_control, Domain::Hibernation);

        // Initialize hibernation clock.
        hib.ctl.write(|w| {
            // Use low-frequency oscillator and enable clock.
            w.oscbyp().clear_bit().clk32en().set_bit()
        });

        // Wait for hibernation module to be ready.
        while hib.ctl.read().wrc().bit_is_clear() {}

        // Enable RTC.
        // SAFETY: Writing to this register is safe because it is data-race free. This guarantee
        // comes from the fact that the hibernation peripheral is borrowed mutably.
        hib.ctl
            .modify(|r, w| unsafe { w.bits(r.bits()).rtcen().set_bit() });

        // Wait for hibernation module to be ready.
        while hib.ctl.read().wrc().bit_is_clear() {}

        Self { hib }
    }

    /// Creates a timer from a duration using the hibernation clock.
    pub fn create_timer(&self, duration: Duration) -> HibTimer {
        HibTimer::new(&self.hib, duration)
    }
}
