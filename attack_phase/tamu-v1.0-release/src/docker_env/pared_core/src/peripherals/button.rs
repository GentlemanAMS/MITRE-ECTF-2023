use cortex_m::asm::delay;
use tm4c123x_hal::gpio::gpiof::PF4;
use tm4c123x_hal::gpio::{Input, PullUp};
use tm4c123x_hal::prelude::*;

pub struct Button {
    pin: PF4<Input<PullUp>>,
    prev: bool,
}

impl Button {
    pub fn new(pin: PF4<Input<PullUp>>) -> Self {
        Self { pin, prev: false }
    }
    fn _is_pressed(&self) -> bool {
        #[allow(deprecated)]
        let ret = self.pin.is_low();
        ret
    }
    pub fn is_pressed(&mut self) -> bool {
        let current = self._is_pressed();
        let mut ret = false;
        if current != self.prev && current {
            delay(10000);
            ret = self._is_pressed();
        }
        self.prev = current;
        ret
    }
}
