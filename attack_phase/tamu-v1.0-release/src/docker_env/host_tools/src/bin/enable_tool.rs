use clap::Parser;
use color_eyre::eyre::Result;
use riir_host_tools::{package_path, Socket, FRAME_OK};
use std::path::PathBuf;
use eeprom_layout::{EnablePackage, Primitive};

#[derive(Parser, Debug)]
#[clap(about, rename_all = "kebab")]
pub struct Args {
    #[clap(long)]
    fob_bridge: u16,
    #[clap(long)]
    package_name: PathBuf,
}

fn main() -> Result<()> {
    color_eyre::install()?;
    let Args {
        fob_bridge,
        package_name,
    } = Args::parse();

    eprintln!("reading binary data from package file...");
    let mut package = EnablePackage::zeroed();
    let p = std::fs::read(package_path(package_name))?;
    package.as_bytes_mut().copy_from_slice(&p);

    eprintln!("Connecting fob socket to serial...");
    let mut sock = Socket::connect(fob_bridge, 5)?;

    eprintln!("Sending enable command to fob...");
    sock.send(b"E")?;

    eprintln!("Sending package to fob...");
    sock.ready_send(package.as_bytes())?;

    eprintln!("Verifying...");
    match sock.recv_byte()? {
        FRAME_OK => println!("Enabled"),
        e => println!("Failed to enable feature, got {:02x}", e),
    }

    Ok(())
}
