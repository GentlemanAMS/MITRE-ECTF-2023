use std::{str, time::Duration};

use clap::Parser;
use ucsc_ectf_util_std::{
    communication::{self, CommunicationError, RxChannel, VerifiedFramedTcpSocket},
    messages::{Uart0Message, UnlockMessage},
    timer::StdTimer,
};

const UNLOCK_BUFF_LEN: usize = 1024;

#[derive(Parser)]
struct Args {
    /// Port number of the socket for the car
    #[arg(long)]
    car_bridge: u16,
}

fn get_unlock_message(car_bridge: u16, buff: &mut [u8]) -> communication::Result<UnlockMessage> {
    let mut socket = VerifiedFramedTcpSocket::keyless_connect(("ectf-net", car_bridge))?;
    let mut timeout_timer = StdTimer::new(Duration::from_secs(5));
    let msg_len = socket.recv_with_data_timeout(buff, &mut timeout_timer)?;
    let msg_bytes = &buff[..msg_len];
    let msg: Uart0Message =
        postcard::from_bytes(msg_bytes).map_err(|_| CommunicationError::RecvError)?;

    match msg {
        Uart0Message::HostUnlock(msg) => Ok(msg),
        _ => Err(CommunicationError::RecvError),
    }
}

fn main() {
    let args = Args::parse();
    let mut unlock_buff = [0; UNLOCK_BUFF_LEN];

    let host_unlock_msg = match get_unlock_message(args.car_bridge, &mut unlock_buff) {
        Ok(msg) => msg,
        Err(_) => {
            println!("Failed to unlock car because unlock message never came or was malformed or the port specified was bad.");

            return;
        }
    };

    println!("Successfully Unlocked Car {}.", host_unlock_msg.car_id);

    println!(
        "Unlock message: {}",
        str::from_utf8(host_unlock_msg.unlock_msg)
            .expect("Unlock message is not a valid UTF-8 string.")
    );

    assert!(host_unlock_msg.feature_nums.len() == host_unlock_msg.feature_msgs.len());

    for (feature_num, feature_msg) in host_unlock_msg
        .feature_nums
        .into_iter()
        .zip(host_unlock_msg.feature_msgs.into_iter())
    {
        let msg_str =
            str::from_utf8(feature_msg).expect("Feature message is not a valid UTF-8 string.");
        println!("Feature message #{feature_num}: {msg_str}");
    }
}
