use std::{error::Error, fs::File, io::Read, path::PathBuf, time::Duration};

use clap::Parser;
use ucsc_ectf_util_std::{
    communication::{self, CommunicationError, RxChannel, TxChannel, VerifiedFramedTcpSocket},
    messages::{EnableFeatureMessage, HostToolAck, PackagedFeatureSigned, Uart0Message},
    timer::StdTimer,
};

const RECV_BUFF_LEN: usize = 128;

#[derive(Parser)]
struct Args {
    /// Bridge for the fob
    #[arg(long)]
    fob_bridge: u16,

    /// Name of the package file
    #[arg(long)]
    package_name: String,
}

fn get_package(
    name: String,
    package_vec: &mut Vec<u8>,
) -> Result<PackagedFeatureSigned, Box<dyn Error>> {
    let mut path = PathBuf::from("/package_dir");
    path.push(name);

    // Technically they can inject a relative path in here instead of
    // just a name but it's not harmful because it's a host tool.
    let mut package_file = File::open(path)?;
    package_file.read_to_end(package_vec)?;

    Ok(postcard::from_bytes(package_vec)?)
}

fn send_package(package: PackagedFeatureSigned, port: u16) -> communication::Result<()> {
    let mut socket = VerifiedFramedTcpSocket::keyless_connect(("ectf-net", port))?;
    let enable_req = Uart0Message::EnableFeatureRequest(EnableFeatureMessage(package));
    let mut enable_req_bytes =
        postcard::to_allocvec(&enable_req).map_err(|_| CommunicationError::InternalError)?;

    socket.send(&mut enable_req_bytes)?;

    let mut buff = [0; RECV_BUFF_LEN];
    let mut timeout_timer = StdTimer::new(Duration::from_millis(4950));
    let resp_len = socket.recv_with_data_timeout(&mut buff, &mut timeout_timer)?;
    let resp = postcard::from_bytes::<Uart0Message>(&buff[..resp_len])
        .map_err(|_| CommunicationError::RecvError)?;

    match resp {
        Uart0Message::EnableFeatureResponse(HostToolAck(true)) => Ok(()),
        _ => Err(CommunicationError::RecvError),
    }
}

fn main() {
    let args = Args::parse();
    let mut package_vec = Vec::new();
    let package = match get_package(args.package_name, &mut package_vec) {
        Ok(package) => package,
        Err(_) => {
            println!("Couldn't find specified package or package malformed.");

            return;
        }
    };

    match send_package(package, args.fob_bridge) {
        Ok(()) => println!("Enabled."),
        Err(_) => println!("Failed to enable feature."),
    }
}
