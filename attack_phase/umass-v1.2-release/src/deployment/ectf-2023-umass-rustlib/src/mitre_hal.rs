use crate::constants::{UART0_BASE, UART1_BASE};
use crate::constants::{UART_RXERROR_BREAK, UART_RXERROR_FRAMING, UART_RXERROR_OVERRUN};

extern "C" {
    fn UARTCharsAvail(Address: u32) -> bool;
    pub(crate) fn GPIOPinRead(port: u32, pins: u8) -> i32;
    pub(crate) fn GPIOPinWrite(ui32Port: u32, ui8Pins: u8, ui8Val: u8);
    fn UARTCharGet(Address: u32) -> i32;
    fn UARTRxErrorGet(ui32Base: u32) -> u32;
    fn UARTRxErrorClear(ui32Base: u32);
    fn UARTCharPut(Address: u32, data: u8);
    pub(crate) fn FlashErase(addr: u32) -> i32;
    pub(crate) fn FlashProgram(data: *const u32, addr: u32, count: u32) -> i32;
    pub(crate) fn EEPROMRead(pui32Data: *mut u32, ui32Address: u32, ui32Count: u32);
    pub(crate) fn EEPROMProgram(pui32Data: *const u32, ui32Address: u32, ui32Count: u32) -> u32;
    pub(crate) fn SysCtlDelay(ui32Count: u32);
    pub(crate) fn timer_get() -> u64;
    pub(crate) fn timer_rtc_start(load_value: u32);
    pub(crate) fn timer_rtc_is_running() -> bool;
    pub(crate) fn timer_rtc_wait_to_expiry(flash_purple: bool);
}

#[repr(transparent)]
pub struct UART(u32);

// Already initialized via registers from the C code
pub(crate) static UART_HOST: UART = UART(UART0_BASE);
pub(crate) static UART_BOARD: UART = UART(UART1_BASE);

impl UART {
    /// Check if there are characters available on a UART interface.
    pub fn available(&self) -> bool {
        unsafe { UARTCharsAvail(self.0) }
    }

    /// Read a byte from a UART interface.
    pub fn read_byte(&self) -> Result<u8,()> {
        loop {
            let val = unsafe { UARTCharGet(self.0) as u8 };
            let err_code = unsafe { UARTRxErrorGet(self.0) } & 0x0f;
            if err_code == 0 {
                break Ok(val);
            }
            if (err_code & UART_RXERROR_OVERRUN) != 0 {
                // Clear error flags before returning error
                unsafe { UARTRxErrorClear(self.0) };
                break Err(());
            }
            if (err_code & UART_RXERROR_FRAMING) != 0 {
                // Framing error occurs on car board if fob board isn't powered on first
                unsafe { UARTRxErrorClear(self.0) };
            }
            if (err_code & UART_RXERROR_BREAK) != 0 {
                // Drop the value and continue the loop after clearing errors
                // Page 909 of datasheet: break error -> emplace 0x00
                unsafe { UARTRxErrorClear(self.0) };
            }
        }
    }
    
    /// Read a sequence of bytes from a UART interface.
    pub fn read(&self, buf: &mut [u8]) -> usize {
        let mut i = 0;
        while i < buf.len() {
            match self.read_byte() {
                Ok(b) => {buf[i] = b;}
                Err(_) => {break;}
            }
            i += 1;
        }
        // Sanity check-should be optimized out
        assert!(i <= buf.len());
        i
    }

    /// Write a byte to a UART interface.
    pub fn write_byte(&self, data: u8) -> () { 
        unsafe { UARTCharPut(self.0, data) }
    }

    /// Write a sequence of bytes to a UART interface.
    pub fn write_bytes(&self, data: &[u8]) {
        data.iter().for_each(|b| self.write_byte(*b));
    }
}
