//! A button module containing an interface to use the onboard SW1 button.

use core::sync::atomic::{AtomicBool, Ordering};
use cortex_m::peripheral::NVIC;
use tm4c123x_hal::{
    bb,
    gpio::{gpiof::PF4, Input, InterruptMode, PullUp},
    interrupt,
    tm4c123x::GPIO_PORTF,
};

/// The pin number of PF4.
const PF4_PIN_NUMBER: u8 = 4;

/// Whether the Sw1ButtonController is initialized.
static SW1_BUTTON_CONTROLLER_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Whether the PF4 pin interrupt has been triggered.
static PF4_ACTIVATED: AtomicBool = AtomicBool::new(false);

#[interrupt]
fn GPIOF() {
    cortex_m::interrupt::free(|_| {
        // Check that Sw1ButtonController is initialized to uphold the safety comment below.
        if !SW1_BUTTON_CONTROLLER_INITIALIZED.load(Ordering::SeqCst) {
            return;
        }

        // SAFETY: This is safe because this is run in an interrupt-free context and this code is run
        // only when there is an instance of Sw1ButtonController. Sw1ButtonController is created only
        // by Runtime, which requires a mutable reference to RuntimePeripherals. RuntimePeripherals
        // can only be created once because it takes ownership of Peripherals and CorePeripherals.
        // RuntimePeripherals also splits GPIO_PORTF into individual pins, destroying GPIO_PORTF in
        // the process, thus making any way of getting and dereferencing the GPIO port F register
        // block unsafe from that point and on. This ensures that the definition of LLVM noalias is
        // satisfied.
        let gpio_portf = unsafe { &*GPIO_PORTF::ptr() };

        // Check that the interrupt was actually triggered by PF4.
        if !bb::read_bit(&gpio_portf.mis, PF4_PIN_NUMBER) {
            return;
        }

        PF4_ACTIVATED.store(true, Ordering::SeqCst);

        // SAFETY: This is safe because the pointer is guaranteed to be valid. The guarantees from
        // the earlier safety comment apply here as well.
        unsafe { bb::change_bit(&gpio_portf.icr, PF4_PIN_NUMBER, true) };
    });
}

/// A struct for the SW1 button controller. The button controller does not provide any debouncing.
pub struct Sw1ButtonController<'a> {
    _pf4: &'a mut PF4<Input<PullUp>>,
}

impl<'a> Sw1ButtonController<'a> {
    /// Initializes the SW1 button controller.
    pub(crate) fn new(pf4: &'a mut PF4<Input<PullUp>>, nvic: &mut NVIC) -> Self {
        const NVIC_GPIOF_ISER_BYTE: usize = 0; // Interrupt number 30 is in byte 0.
        const NVIC_GPIOF_ISER_BIT: u32 = 30; // Interrupt number 30.
        SW1_BUTTON_CONTROLLER_INITIALIZED.store(true, Ordering::SeqCst);
        pf4.set_interrupt_mode(InterruptMode::EdgeRising);

        // SAFETY: Unmasking the interrupt is safe because the interrupt handler for GPIOF defined
        // in this file only relies on data local to this module, and GPIO_PORTF. The safety of using
        // GPIO_PORTF is explained in the safety comment of the GPIOF interrupt handler. Since nothing
        // in this module relies on a mask-based critical section, this write is safe.
        unsafe { nvic.iser[NVIC_GPIOF_ISER_BYTE].write(1 << NVIC_GPIOF_ISER_BIT) };

        Self { _pf4: pf4 }
    }

    /// Returns whether an activation has been occurred for the SW1 button. Will continue to return
    /// true until the activation is cleared with `Sw1ButtonController::clear_activation()`.
    pub fn poll_for_activation(&self) -> bool {
        PF4_ACTIVATED.load(Ordering::SeqCst)
    }

    /// Clears the activation boolean for the SW1 button.
    pub fn clear_activation(&self) {
        PF4_ACTIVATED.store(false, Ordering::SeqCst);
    }
}

impl<'a> Drop for Sw1ButtonController<'a> {
    fn drop(&mut self) {
        SW1_BUTTON_CONTROLLER_INITIALIZED.store(false, Ordering::SeqCst);
    }
}
