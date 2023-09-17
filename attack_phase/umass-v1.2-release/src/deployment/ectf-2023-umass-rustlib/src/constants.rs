#![allow(dead_code)]
pub(crate) const GPIO_PORTB_BASE : u32 = 0x40005000;
pub(crate) const GPIO_PORTF_BASE : u32 = 0x40025000;
pub(crate) const GPIO_PIN_0 : u8 = 0x00000001;
pub(crate) const GPIO_PIN_1 : u8 = 0x00000002;
pub(crate) const GPIO_PIN_2 : u8 = 0x00000004;
pub(crate) const GPIO_PIN_3 : u8 = 0x00000008;
pub(crate) const GPIO_PIN_4 : u8 = 0x00000010;

pub(crate) const UART0_BASE : u32 = 0x4000C000;
pub(crate) const UART1_BASE : u32 = 0x4000D000;

pub(crate) const UART_RXERROR_OVERRUN : u32 = 0x00000008;
pub(crate) const UART_RXERROR_BREAK : u32   = 0x00000004;
pub(crate) const UART_RXERROR_PARITY : u32  = 0x00000002;
pub(crate) const UART_RXERROR_FRAMING : u32 = 0x00000001;

pub(crate) const TIMER_PER_SEC : u32 = 80_000_000;
