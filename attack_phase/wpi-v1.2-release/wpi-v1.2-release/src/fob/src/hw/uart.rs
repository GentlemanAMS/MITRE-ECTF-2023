//! UART communication support

#![allow(dead_code)] // Remove this for actual use, just so the compiler doesn't complain for the
                     // hello world.
use cortex_m::singleton;

use crate::tivaware::{
    GPIOPadConfigSet, GPIOPinConfigure, GPIOPinTypeUART, SysCtlClockGet, SysCtlPeripheralEnable,
    UARTCharGet, UARTCharPut, UARTCharsAvail, UARTConfigSetExpClk, UARTFIFOLevelSet, GPIO_PA0_U0RX,
    GPIO_PA1_U0TX, GPIO_PIN_0, GPIO_PIN_1, GPIO_PIN_TYPE_STD_WPU, GPIO_PORTA_BASE,
    GPIO_PORTB_BASE, GPIO_STRENGTH_2MA, SYSCTL_PERIPH_GPIOA, SYSCTL_PERIPH_GPIOB,
    SYSCTL_PERIPH_UART0, SYSCTL_PERIPH_UART1, UART0_BASE, UART1_BASE, UART_CONFIG_PAR_NONE,
    UART_CONFIG_STOP_ONE, UART_CONFIG_WLEN_8, UART_FIFO_RX1_8, UART_FIFO_TX1_8, UARTFIFOEnable, GPIO_PB0_U1RX, GPIO_PB1_U1TX,
};

use crate::comms::io::IO;
use crate::comms::packet::PacketIO;
use crate::comms::io::Error;

/// A UART communication channel.
pub trait UartIO: IO {
    /// The base address of the UART peripheral's registers.
    const UART_BASE: u32;
}

impl<T: UartIO> IO for T {
    fn data_avail(&self) -> bool {
        unsafe { UARTCharsAvail(Self::UART_BASE) }
    }

    fn write_byte(&self, byte: u8) {
        unsafe { UARTCharPut(Self::UART_BASE, byte) }
    }

    fn read_byte(&self) -> u8 {
        unsafe { UARTCharGet(Self::UART_BASE) as u8 }
    }

    fn read_byte_timeout<'a, 'b: 'a>(&'a self, time_keeper: &'b dyn crate::utils::timing::Timeout) -> Result<u8, Error> {
        loop {
            if time_keeper.has_expired() {
                return Err(Error::TimedOut);
            }

            if self.data_avail() {
                return Ok(self.read_byte());
            }
        }
    }
}

/// Board<->Host UART communication channel.
pub struct HostUart;
impl HostUart {
    pub fn new() -> Option<&'static mut Self> {
        unsafe {
            SysCtlPeripheralEnable(SYSCTL_PERIPH_UART0);
            SysCtlPeripheralEnable(SYSCTL_PERIPH_GPIOA);

            GPIOPinConfigure(GPIO_PA0_U0RX);
            GPIOPinConfigure(GPIO_PA1_U0TX);

            GPIOPinTypeUART(GPIO_PORTA_BASE, (GPIO_PIN_0 as u8) | (GPIO_PIN_1 as u8));
            GPIOPadConfigSet(
                GPIO_PORTA_BASE,
                (GPIO_PIN_0 as u8) | (GPIO_PIN_1 as u8),
                GPIO_STRENGTH_2MA,
                GPIO_PIN_TYPE_STD_WPU,
            );

            UARTConfigSetExpClk(
                UART0_BASE,
                SysCtlClockGet(),
                115200,
                UART_CONFIG_WLEN_8 | UART_CONFIG_STOP_ONE | UART_CONFIG_PAR_NONE,
            );
            UARTFIFOLevelSet(UART0_BASE, UART_FIFO_TX1_8, UART_FIFO_RX1_8);
            UARTFIFOEnable(UART0_BASE);
        };

        singleton!(: HostUart = HostUart {})
    }
}

impl UartIO for HostUart {
    const UART_BASE: u32 = UART0_BASE;
}

impl PacketIO for HostUart {}

/// Board<->Board UART communication channel.
pub struct BridgeUart;
impl BridgeUart {
    pub fn new() -> Option<&'static mut Self> {
        unsafe {
            SysCtlPeripheralEnable(SYSCTL_PERIPH_UART1);
            SysCtlPeripheralEnable(SYSCTL_PERIPH_GPIOB);

            GPIOPinConfigure(GPIO_PB0_U1RX);
            GPIOPinConfigure(GPIO_PB1_U1TX);

            GPIOPinTypeUART(GPIO_PORTB_BASE, (GPIO_PIN_0 as u8) | (GPIO_PIN_1 as u8));
            GPIOPadConfigSet(GPIO_PORTB_BASE, (GPIO_PIN_0 as u8) | (GPIO_PIN_1 as u8), GPIO_STRENGTH_2MA, GPIO_PIN_TYPE_STD_WPU);

            UARTConfigSetExpClk(
                UART1_BASE,
                SysCtlClockGet(),
                115200,
                UART_CONFIG_WLEN_8 | UART_CONFIG_STOP_ONE | UART_CONFIG_PAR_NONE,
            );
            UARTFIFOLevelSet(UART1_BASE, UART_FIFO_TX1_8, UART_FIFO_RX1_8);
            UARTFIFOEnable(UART1_BASE);
        };

        singleton!(: BridgeUart = BridgeUart {})
    }
}

impl UartIO for BridgeUart {
    const UART_BASE: u32 = UART1_BASE;
}

impl PacketIO for BridgeUart {}
