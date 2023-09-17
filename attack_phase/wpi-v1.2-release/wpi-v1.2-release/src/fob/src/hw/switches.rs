use crate::tivaware::{
    GPIOPadConfigSet, GPIOPinRead, GPIOPinTypeGPIOInput, GPIO_PIN_4, GPIO_PIN_TYPE_STD_WPU,
    GPIO_PORTF_BASE, GPIO_STRENGTH_4MA,
};

pub fn setup_sw1() {
    unsafe {
        GPIOPinTypeGPIOInput(GPIO_PORTF_BASE, GPIO_PIN_4 as u8);
        GPIOPadConfigSet(
            GPIO_PORTF_BASE,
            GPIO_PIN_4 as u8,
            GPIO_STRENGTH_4MA,
            GPIO_PIN_TYPE_STD_WPU,
        );
    }
}

pub fn read_sw1() -> bool {
    let switch_read_result: i32 = unsafe { GPIOPinRead(GPIO_PORTF_BASE, GPIO_PIN_4 as u8) };
    switch_read_result == 0 // 0 means switch is pressed
}
