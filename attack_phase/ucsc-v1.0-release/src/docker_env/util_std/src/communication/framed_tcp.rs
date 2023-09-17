use std::{
    io::{Read, Write},
    net::{TcpStream, ToSocketAddrs},
    time::{Duration, Instant},
};

use ucsc_ectf_util_common::{
    communication::{
        self,
        lower_layers::framing::{bogoframing, Frame, FramedTxChannel},
        CommunicationError, RxChannel,
    },
    timer::Timer,
};

const UART_FIFO_LEN: usize = 16;

/// The minimum size a framed UART message can be.
pub(crate) const MIN_FRAMED_UART_MESSAGE: usize = UART_FIFO_LEN;

fn flush_rx_stream(stream: &mut TcpStream) -> Result<(), CommunicationError> {
    stream
        .set_nonblocking(true)
        .map_err(|_| CommunicationError::InternalError)?;

    let _ = stream.read_to_end(&mut Vec::new());

    stream
        .set_nonblocking(false)
        .map_err(|_| CommunicationError::InternalError)?;

    Ok(())
}

pub(crate) fn connect(
    addr: impl ToSocketAddrs,
) -> Result<(FramedTcpTxChannel, FramedTcpRxChannel), CommunicationError> {
    let stream_tx = TcpStream::connect(addr).map_err(|_| CommunicationError::InternalError)?;
    let mut stream_rx = stream_tx
        .try_clone()
        .map_err(|_| CommunicationError::InternalError)?;

    stream_tx
        .set_nodelay(true)
        .map_err(|_| CommunicationError::InternalError)?;

    flush_rx_stream(&mut stream_rx)?;

    Ok((FramedTcpTxChannel(stream_tx), FramedTcpRxChannel(stream_rx)))
}

fn read_byte(stream: &mut TcpStream) -> Result<u8, CommunicationError> {
    let mut data = [0; 1];

    // Our socket should never close, so if it does (returns 0), it's an error
    match stream.read(&mut data) {
        Ok(1..) => Ok(data[0]),
        _ => Err(CommunicationError::RecvError),
    }
}

pub struct FramedTcpRxChannel(TcpStream);

impl RxChannel for FramedTcpRxChannel {
    fn recv_with_data_timeout<T: Timer>(
        &mut self,
        dest: &mut [u8],
        timer: &mut T,
    ) -> communication::Result<usize> {
        let timeout_duration = timer.duration();

        // We keep track of this to not kill our CPUs on host tools :)
        self.0
            .set_read_timeout(Some(timeout_duration))
            .map_err(|_| CommunicationError::InternalError)?;

        bogoframing::recv_frame_with_timeout(
            self,
            dest,
            timer,
            |ch| read_byte(&mut ch.0),
            MIN_FRAMED_UART_MESSAGE,
        )
    }

    fn recv_with_timeout<T: Timer>(
        &mut self,
        dest: &mut [u8],
        timer: &mut T,
    ) -> communication::Result<usize> {
        // This implementation is here for completeness. We won't be using this...

        let start_instant = Instant::now();
        let timeout_duration = timer.duration();

        bogoframing::recv_frame_with_timeout(
            self,
            dest,
            timer,
            |ch| {
                let read_timeout = timeout_duration.saturating_sub(Instant::now() - start_instant);
                if read_timeout == Duration::ZERO {
                    return Err(CommunicationError::RecvError);
                }

                // We keep track of this to not kill our CPUs on host tools :)
                ch.0.set_read_timeout(Some(read_timeout))
                    .map_err(|_| CommunicationError::InternalError)?;

                read_byte(&mut ch.0)
            },
            MIN_FRAMED_UART_MESSAGE,
        )
    }
}

pub struct FramedTcpTxChannel(TcpStream);

impl FramedTxChannel for FramedTcpTxChannel {
    fn frame<'a, const FRAME_CT: usize>(
        &mut self,
        frame: impl FnOnce() -> Result<Frame<'a, FRAME_CT>, CommunicationError>,
    ) -> communication::Result<()> {
        bogoframing::frame_bogoframe(
            self,
            frame()?,
            |ch, s| ch.0.write_all(s).map_err(|_| CommunicationError::SendError),
            MIN_FRAMED_UART_MESSAGE,
        )
    }
}
