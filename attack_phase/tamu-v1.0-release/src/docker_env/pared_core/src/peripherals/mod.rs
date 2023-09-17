pub mod button;
pub mod eeprom;
pub mod uart;

use tm4c123x_hal::gpio;
use tm4c123x_hal::tm4c123x::FLASH_CTRL;
use tm4c123x_hal::prelude::*;
use tm4c123x_hal::serial::{NewlineMode, Serial};
use tm4c123x_hal::sysctl::{CrystalFrequency, Oscillator, PllOutputFrequency, SystemClock};
use tm4c123x_hal::Peripherals as RawPeripherals;

pub use button::Button;
pub use eeprom::Eeprom;
pub use uart::{Uart0, Uart1};

pub struct Peripherals {
    pub eeprom: Eeprom,
    pub uart_ht: Uart0,
    pub uart_board: Uart1,
    pub button: Button,
}

impl Peripherals {
    pub fn disable_writes(f: &mut FLASH_CTRL) {
        // FMPPE0: 0 to 64 KB
        // FMPPE1: 65 to 128 KB
        // FMPPE2: 129 to 192 KB
        // FMPPE3: 193 to 256 KB
        f.fmppe0.write(|w| unsafe { w.bits(0) });
        f.fmppe1.write(|w| unsafe { w.bits(0) });
        f.fmppe2.write(|w| unsafe { w.bits(0) });
        f.fmppe3.write(|w| unsafe { w.bits(0) });
    }
    
    pub fn init() -> Self {
        let mut p = RawPeripherals::take().unwrap();
        let mut sc = p.SYSCTL.constrain();
        sc.clock_setup.oscillator = Oscillator::Main(
            CrystalFrequency::_16mhz,
            SystemClock::UsePll(PllOutputFrequency::_80_00mhz),
        );
        let eeprom = Eeprom::init(p.EEPROM, &mut sc);
        let clocks = sc.clock_setup.freeze();
        let mut porta = p.GPIO_PORTA.split(&sc.power_control);
        let mut portb = p.GPIO_PORTB.split(&sc.power_control);
        let portf = p.GPIO_PORTF.split(&sc.power_control);
        let tx0 = porta.pa1.into_af_push_pull::<gpio::AF1>(&mut porta.control);
        let rx0 = porta.pa0.into_af_push_pull::<gpio::AF1>(&mut porta.control);
        let tx1 = portb.pb1.into_af_push_pull::<gpio::AF1>(&mut portb.control);
        let rx1 = portb.pb0.into_af_push_pull::<gpio::AF1>(&mut portb.control);
        let button = Button::new(portf.pf4.into_pull_up_input());
        let uart_ht = Uart0(Serial::uart0(
            p.UART0,
            tx0,
            rx0,
            (),
            (),
            115_200.bps(),
            NewlineMode::Binary,
            &clocks,
            &sc.power_control,
        ));
        let uart_board = Uart1(Serial::uart1(
            p.UART1,
            tx1,
            rx1,
            (),
            (),
            115_200.bps(),
            NewlineMode::Binary,
            &clocks,
            &sc.power_control,
        ));
        Self::disable_writes(&mut p.FLASH_CTRL);
        Self {
            eeprom,
            uart_ht,
            uart_board,
            button,
        }
    }
}
