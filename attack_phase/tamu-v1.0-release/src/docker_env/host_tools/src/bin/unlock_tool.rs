use clap::Parser;
use color_eyre::Result;
use riir_host_tools::{FRAME_OK, Socket};
use std::string::String;

#[derive(Parser, Debug)]
#[clap(about, rename_all = "kebab")]
pub struct Args {
    #[clap(long)]
    car_bridge: u16,
}

fn main() -> Result<()> {
    color_eyre::install()?;
    let Args { car_bridge } = Args::parse();

    eprintln!("Connecting car socket to serial...");
    let mut sock = Socket::connect(car_bridge, 5)?;

    eprintln!("Trying to receive data while unlocking...");
    loop {
        let x = sock.recv(1)?;
        if x[0] == FRAME_OK {
            break
        }
        print!("{}", String::from_utf8(x).unwrap());

    }
    Ok(())
}
