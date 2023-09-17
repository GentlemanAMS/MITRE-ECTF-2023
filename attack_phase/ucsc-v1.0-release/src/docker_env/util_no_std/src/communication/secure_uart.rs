use super::{
    lower_layers::crypto::{
        KeyedChannel, RandomSource, XChacha20Poly1305RxChannel, XChacha20Poly1305TxChannel,
    },
    uart::{FramedUartRxChannel, FramedUartTxChannel},
    RxChannel, TxChannel,
};
use crate::random::fill_rand_slice;
use chacha20poly1305::Key;
use tm4c123x_hal::{
    serial::{Rx, RxPin, Tx, TxPin},
    tm4c123x::{UART0, UART1},
};
use ucsc_ectf_util_common::timer::Timer;

type EncryptedUartTxChannel<'a, UART, TX> =
    XChacha20Poly1305TxChannel<FramedUartTxChannel<'a, UART, TX>, UartRandomSource>;

type EncryptedUartRxChannel<'a, UART, RX> =
    XChacha20Poly1305RxChannel<FramedUartRxChannel<'a, UART, RX>>;

/// The [`RandomSource`] used for encrypted UART channels.
pub struct UartRandomSource {
    _not_constructible: (), // Makes this not publicly constructible.
}

impl RandomSource for UartRandomSource {
    fn fill_rand_slice<T: AsMut<[u8]>>(&mut self, mut slice_ref: T) {
        fill_rand_slice(slice_ref.as_mut());
    }
}

macro_rules! uart_impl {
    ($ctr_ty:ident, $uart_typ:ty, $fn_name:ident,$keyless_fn_name:ident, $tx_ctor:ident, $rx_ctor:ident) => {
        /// An optionally bi-directionally encrypted and authenticated way to send and
        /// receive UART transmissions. Currently, only UART0 and UART1 are supported.
        /// Use associated function ``Self::new`` to create secure instances of this struct.
        /// If ``Self::without_key()`` is used, then the channel will be encrypted
        /// with a constant key, meaning no confidentiality will be provided.
        /// However, the data will still have essentially a checksum attached
        /// to protect against data corruption not from a malicious entity. See
        /// [`XChacha20Poly1305RxChannel`] and [`XChacha20Poly1305TxChannel`]
        /// for how message confidentiality and integrity is guaranteed for transmissions
        /// in this struct.
        ///
        /// To frame the UART data sent and received, BogoFraming is used.
        ///
        /// ## BogoFraming
        /// Each message sent/received will be hex encoded and decoded, delimited by a NULL (\0) character
        /// at the start and at the end. Messages must be at least 1 character long.
        pub struct $ctr_ty<'a, TX, RX>
        where
            TX: TxPin<$uart_typ>,
            RX: RxPin<$uart_typ>,
        {
            tx_channel: EncryptedUartTxChannel<'a, $uart_typ, TX>,
            rx_channel: EncryptedUartRxChannel<'a, $uart_typ, RX>,
        }

        impl<'a, TX, RX> $ctr_ty<'a, TX, RX>
        where
            TX: TxPin<$uart_typ>,
            RX: RxPin<$uart_typ>,
        {
            /// Creates a new UART controller using the provided split
            /// [Serial](tm4c123x_hal::serial::Serial) struct and encryption
            /// and decryption keys. The encryption used is symmetric. See
            /// the struct-level documentation for more info.
            pub fn $fn_name(
                tx: &'a mut Tx<$uart_typ, TX, ()>,
                rx: &'a mut Rx<$uart_typ, RX, ()>,
                rx_key: &Key,
                tx_key: &Key,
            ) -> Self {
                let tx_channel = EncryptedUartTxChannel::new(
                    FramedUartTxChannel::$tx_ctor(tx),
                    UartRandomSource {
                        _not_constructible: (),
                    },
                    tx_key,
                );
                let rx_channel =
                    EncryptedUartRxChannel::new(FramedUartRxChannel::$rx_ctor(rx), rx_key);

                Self {
                    tx_channel,
                    rx_channel,
                }
            }

            /// Creates a new UART controller using the provided split
            /// [Serial](tm4c123x_hal::serial::Serial) struct and an insecure,
            /// constant encryption and decryption key. See the struct-level
            /// documentation for more info.
            pub fn $keyless_fn_name(
                tx: &'a mut Tx<$uart_typ, TX, ()>,
                rx: &'a mut Rx<$uart_typ, RX, ()>,
            ) -> Self {
                Self::$fn_name(tx, rx, &Default::default(), &Default::default())
            }

            /// Changes the encryption key used for the UART TX channel to the provided key.
            pub fn change_tx_key(
                &mut self,
                new_key: &<EncryptedUartTxChannel<$uart_typ, TX> as KeyedChannel>::KeyType,
            ) {
                self.tx_channel.change_key(new_key);
            }

            /// Changes the decryption key used for the UART RX channel to the provided key.
            pub fn change_rx_key(
                &mut self,
                new_key: &<EncryptedUartRxChannel<$uart_typ, RX> as KeyedChannel>::KeyType,
            ) {
                self.rx_channel.change_key(new_key);
            }
        }

        impl<'a, TX, RX> RxChannel for $ctr_ty<'a, TX, RX>
        where
            TX: TxPin<$uart_typ>,
            RX: RxPin<$uart_typ>,
        {
            fn recv_with_timeout<T: Timer>(
                &mut self,
                dest: &mut [u8],
                timer: &mut T,
            ) -> super::Result<usize> {
                self.rx_channel.recv_with_timeout(dest, timer)
            }

            fn recv_with_data_timeout<T: Timer>(
                &mut self,
                dest: &mut [u8],
                timer: &mut T,
            ) -> super::Result<usize> {
                self.rx_channel.recv_with_data_timeout(dest, timer)
            }
        }

        impl<'a, TX, RX> TxChannel for $ctr_ty<'a, TX, RX>
        where
            TX: TxPin<$uart_typ>,
            RX: RxPin<$uart_typ>,
        {
            fn send(&mut self, src: &mut [u8]) -> super::Result<()> {
                self.tx_channel.send(src)
            }
        }
    };
}

uart_impl!(
    Uart0Controller,
    UART0,
    new,
    without_key,
    new_uart0_tx_channel,
    new_uart0_rx_channel
);
uart_impl!(
    Uart1Controller,
    UART1,
    new,
    without_key,
    new_uart1_tx_channel,
    new_uart1_rx_channel
);
