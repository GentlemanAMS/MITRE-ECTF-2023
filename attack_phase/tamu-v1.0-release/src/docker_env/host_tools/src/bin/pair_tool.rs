use std::thread;

use clap::Parser;
use color_eyre::eyre::{ensure, Result};
use riir_host_tools::Socket;

fn parse_pin(s: &str) -> Result<u32> {
    ensure!(s.len() == 6, "pin must have 6 digits");
    Ok(u32::from_str_radix(s, 16)?)
}

#[derive(Parser, Debug)]
#[clap(about, rename_all = "kebab")]
pub struct Args {
    #[clap(long)]
    unpaired_fob_bridge: u16,
    #[clap(long)]
    paired_fob_bridge: u16,
    #[clap(long, value_parser = parse_pin)]
    pair_pin: u32,
}

fn main() -> Result<()> {
    color_eyre::install()?;
    let Args {
        unpaired_fob_bridge,
        paired_fob_bridge,
        pair_pin,
    } = Args::parse();

    eprintln!("Connecting unpaired socket to serial...");
    let mut unpaired_sock = Socket::connect(unpaired_fob_bridge, 5)?;

    eprintln!("Connecting paired socket to serial...");
    let mut paired_sock = Socket::connect(paired_fob_bridge, 5)?;

    eprintln!("Sending pair command to both fobs...");
    paired_sock.send(b"P")?;
    paired_sock.recv(1)?;
    unpaired_sock.send(b"U")?;

    eprintln!("Sending pin to paired fob...");
    paired_sock.ready_send(&pair_pin.to_le_bytes())?;

    eprintln!("Verifying...");

    thread::spawn(move || -> Result<()> {
        for _ in 0..144 {
            let x = unpaired_sock.recv_byte()?;
            print!("uf:{:02x?}", x);
        }
        let x = unpaired_sock.recv_byte()?;
        println!("uf:{:02x?}", x);
        Ok(())
    });

    for _ in 0..144 {
        let x = paired_sock.recv_byte()?;
        print!("pf:{:02x?}", x);
    }
    let x = paired_sock.recv_byte()?;
    println!("pf:{:02x?}", x);

    Ok(())
}
