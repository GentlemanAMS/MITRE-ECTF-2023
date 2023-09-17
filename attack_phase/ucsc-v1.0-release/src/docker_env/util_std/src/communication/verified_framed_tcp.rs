use std::net::ToSocketAddrs;

use rand::RngCore;
use ucsc_ectf_util_common::{
    communication::{
        self,
        lower_layers::crypto::{
            RandomSource, XChacha20Poly1305RxChannel, XChacha20Poly1305TxChannel,
        },
        RxChannel, TxChannel,
    },
    timer::Timer,
};

use super::framed_tcp::{self, FramedTcpRxChannel, FramedTcpTxChannel};

type VerifiedFramedTcpTxChannel = XChacha20Poly1305TxChannel<FramedTcpTxChannel, StdRandomSource>;

type VerifiedFramedTcpRxChannel = XChacha20Poly1305RxChannel<FramedTcpRxChannel>;

/// This [`RandomSource`] uses OS-provided entropy to generate random numbers.
pub struct StdRandomSource {
    _not_constructible: (), // Makes this struct un-constructible
}

impl RandomSource for StdRandomSource {
    fn fill_rand_slice<T: AsMut<[u8]>>(&mut self, mut slice_ref: T) {
        rand::thread_rng().fill_bytes(slice_ref.as_mut());
    }
}

/// This struct contains an [`RxChannel`] and [`TxChannel`] for a TCP socket that frames messages
/// using BogoFraming. See the [`framing`](super::lower_layers::framing) module for more information
/// on this type of framing.
pub struct VerifiedFramedTcpSocket {
    tx_channel: VerifiedFramedTcpTxChannel,
    rx_channel: VerifiedFramedTcpRxChannel,
}

impl VerifiedFramedTcpSocket {
    /// This connects to the provided address over TCP and creates a [`VerifiedFramedTcpSocket`]
    /// from the connection.
    pub fn keyless_connect(addr: impl ToSocketAddrs) -> communication::Result<Self> {
        let (framed_tx_channel, framed_rx_channel) = framed_tcp::connect(addr)?;
        let tx_channel = XChacha20Poly1305TxChannel::new(
            framed_tx_channel,
            StdRandomSource {
                _not_constructible: (),
            },
            &Default::default(),
        );
        let rx_channel = XChacha20Poly1305RxChannel::new(framed_rx_channel, &Default::default());

        Ok(VerifiedFramedTcpSocket {
            tx_channel,
            rx_channel,
        })
    }
}

impl RxChannel for VerifiedFramedTcpSocket {
    fn recv_with_data_timeout<T: Timer>(
        &mut self,
        dest: &mut [u8],
        timer: &mut T,
    ) -> communication::Result<usize> {
        self.rx_channel.recv_with_data_timeout(dest, timer)
    }

    fn recv_with_timeout<T: Timer>(
        &mut self,
        dest: &mut [u8],
        timer: &mut T,
    ) -> communication::Result<usize> {
        self.rx_channel.recv_with_timeout(dest, timer)
    }
}

impl TxChannel for VerifiedFramedTcpSocket {
    fn send(&mut self, src: &mut [u8]) -> communication::Result<()> {
        self.tx_channel.send(src)
    }
}
