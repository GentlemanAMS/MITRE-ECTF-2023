use core::ops::Deref;

use cortex_m::prelude::_embedded_hal_serial_Read;
use tm4c123x_hal::{
    serial::{Rx, RxPin, Tx, TxPin},
    tm4c123x::{uart0, UART0, UART1},
};
use ucsc_ectf_util_common::{
    communication::{lower_layers::framing::bogoframing, CommunicationError},
    timer::Timer,
};

use crate::communication::{
    self,
    lower_layers::framing::{Frame, FramedTxChannel},
    RxChannel,
};

const UART_FIFO_LEN: usize = 16;

/// The minimum size a framed UART message can be.
pub const MIN_FRAMED_UART_MESSAGE: usize = UART_FIFO_LEN;

/// A [`FramedTxChannel`] for transmitting UART data. This channel is unreliable and can lose bytes
/// in transmission. It is also insecure and should be wrapped around one of the channels in the
/// [`crypto`](crate::communication::lower_layers::crypto) layer for confidentiality and/or integrity.
/// A message sent by this channel must be at least [`MIN_FRAMED_UART_MESSAGE`] bytes long.
/// See the module-level documentation for details on how framing works for this channel.
pub struct FramedUartTxChannel<'a, UART, TX>
where
    UART: Deref<Target = uart0::RegisterBlock>,
    TX: TxPin<UART>,
{
    tx: &'a mut Tx<UART, TX, ()>,
}

impl<'a, TX> FramedUartTxChannel<'a, UART0, TX>
where
    TX: TxPin<UART0>,
{
    /// Creates a new [`FramedUartTxChannel`] for UART0 tranmission given the [`Tx`] end
    /// of a split [`Serial`](tm4c123x_hal::serial::Serial).
    pub fn new_uart0_tx_channel(tx: &'a mut Tx<UART0, TX, ()>) -> Self {
        Self { tx }
    }
}

impl<'a, TX> FramedUartTxChannel<'a, UART1, TX>
where
    TX: TxPin<UART1>,
{
    /// Creates a new [`FramedUartTxChannel`] for UART1 tranmission given the [`Tx`] end
    /// of a split [`Serial`](tm4c123x_hal::serial::Serial).
    pub fn new_uart1_tx_channel(tx: &'a mut Tx<UART1, TX, ()>) -> Self {
        Self { tx }
    }
}

/// An [`RxChannel`] for receiving UART data. This channel is unreliable and might not receive transmitted bytes.
/// It can also receive data that was never sent, receive merged frames, or split a message. It is also insecure
/// and should be wrapped around one of the channels in the [`crypto`](crate::communication::lower_layers::crypto)
/// layer for confidentiality and/or integrity. See the module-level documentation for details on how framing works
/// for this channel.
pub struct FramedUartRxChannel<'a, UART, RX>
where
    UART: Deref<Target = uart0::RegisterBlock>,
    RX: RxPin<UART>,
{
    rx: &'a mut Rx<UART, RX, ()>,
}

impl<'a, RX> FramedUartRxChannel<'a, UART0, RX>
where
    RX: RxPin<UART0>,
{
    /// Creates a new [`FramedUartRxChannel`] for UART0 tranmission given the [`Rx`] end
    /// of a split [`Serial`](tm4c123x_hal::serial::Serial).
    pub fn new_uart0_rx_channel(rx: &'a mut Rx<UART0, RX, ()>) -> Self {
        Self { rx }
    }
}

impl<'a, RX> FramedUartRxChannel<'a, UART1, RX>
where
    RX: RxPin<UART1>,
{
    /// Creates a new [`FramedUartRxChannel`] for UART1 tranmission given the [`Tx`] end
    /// of a split [`Serial`](tm4c123x_hal::serial::Serial).
    pub fn new_uart1_rx_channel(rx: &'a mut Rx<UART1, RX, ()>) -> Self {
        Self { rx }
    }
}

impl<'a, TX> FramedTxChannel for FramedUartTxChannel<'a, UART0, TX>
where
    TX: TxPin<UART0>,
{
    fn frame<'b, const FRAME_CT: usize>(
        &mut self,
        frame: impl FnOnce() -> communication::Result<Frame<'b, FRAME_CT>>,
    ) -> communication::Result<()> {
        bogoframing::frame_bogoframe(
            self,
            frame()?,
            |ch, s| {
                ch.tx.write_all(s);
                Ok(())
            },
            MIN_FRAMED_UART_MESSAGE,
        )
    }
}

impl<'a, TX> FramedTxChannel for FramedUartTxChannel<'a, UART1, TX>
where
    TX: TxPin<UART1>,
{
    fn frame<'b, const FRAME_CT: usize>(
        &mut self,
        frame: impl FnOnce() -> communication::Result<Frame<'b, FRAME_CT>>,
    ) -> communication::Result<()> {
        bogoframing::frame_bogoframe(
            self,
            frame()?,
            |ch, s| {
                ch.tx.write_all(s);
                Ok(())
            },
            MIN_FRAMED_UART_MESSAGE,
        )
    }
}

impl<'a, RX> RxChannel for FramedUartRxChannel<'a, UART0, RX>
where
    RX: RxPin<UART0>,
{
    fn recv_with_data_timeout<T: Timer>(
        &mut self,
        dest: &mut [u8],
        timer: &mut T,
    ) -> communication::Result<usize> {
        bogoframing::recv_frame_with_data_timeout(
            self,
            dest,
            timer,
            |s| s.rx.read().map_err(|_| CommunicationError::RecvError),
            MIN_FRAMED_UART_MESSAGE,
        )
    }

    fn recv_with_timeout<T: Timer>(
        &mut self,
        dest: &mut [u8],
        timer: &mut T,
    ) -> ucsc_ectf_util_common::communication::Result<usize> {
        bogoframing::recv_frame_with_timeout(
            self,
            dest,
            timer,
            |s| s.rx.read().map_err(|_| CommunicationError::RecvError),
            MIN_FRAMED_UART_MESSAGE,
        )
    }
}

impl<'a, RX> RxChannel for FramedUartRxChannel<'a, UART1, RX>
where
    RX: RxPin<UART1>,
{
    fn recv_with_data_timeout<T: Timer>(
        &mut self,
        dest: &mut [u8],
        timer: &mut T,
    ) -> communication::Result<usize> {
        bogoframing::recv_frame_with_data_timeout(
            self,
            dest,
            timer,
            |s| s.rx.read().map_err(|_| CommunicationError::RecvError),
            MIN_FRAMED_UART_MESSAGE,
        )
    }

    fn recv_with_timeout<T: Timer>(
        &mut self,
        dest: &mut [u8],
        timer: &mut T,
    ) -> ucsc_ectf_util_common::communication::Result<usize> {
        bogoframing::recv_frame_with_timeout(
            self,
            dest,
            timer,
            |s| s.rx.read().map_err(|_| CommunicationError::RecvError),
            MIN_FRAMED_UART_MESSAGE,
        )
    }
}
