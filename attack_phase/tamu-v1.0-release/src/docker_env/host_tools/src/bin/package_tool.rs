use blake2::{Blake2s256, Digest};
use clap::Parser;
use color_eyre::{eyre::eyre, Result};
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use riir_host_tools::package_path;
use std::{path::PathBuf, string::String};
use eeprom_layout::{EnablePackage, Primitive};

#[derive(Parser, Debug)]
#[clap(about, rename_all = "kebab")]
pub struct Args {
    #[clap(long)]
    package_name: PathBuf,
    #[clap(long)]
    car_id: u32,
    #[clap(long)]
    feature_number: u32,
}

fn main() -> Result<()> {
    color_eyre::install()?;
    let Args {
        package_name,
        car_id,
        feature_number,
    } = Args::parse();

    eprintln!("Reading package signing key from secrets...");
    let signing_key = {
        let bytes = std::fs::read("/secrets/package_key")?;
        SigningKey::from_bytes(&bytes)
            .map_err(|_| eyre!("error reading package signing key"))?
    };

    eprintln!("Signing and hashing...");
    let hash = {
        let mut hasher = Blake2s256::new();
        hasher.update(car_id.to_le_bytes());
        hasher.update(feature_number.to_le_bytes());
        hasher.finalize()
    };

    let signature: Signature = signing_key.sign(&hash);

    let package = EnablePackage {
        car_id,
        feature_number,
        hash,
        signature,
    };

    eprintln!("Writing to file...");
    std::fs::write(package_path(package_name), &package.as_bytes())?;

    Ok(())
}
