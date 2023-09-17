use std::{
    fs::File,
    io::{Read, Write},
    path::PathBuf,
};

use clap::Parser;
use k256::ecdsa::{signature::Signer, Signature, SigningKey};
use postcard::to_allocvec;
use ucsc_ectf_util_std::messages::{PackagedFeatureSigned, PackagedFeatureUnsigned};

#[derive(Parser)]
struct Args {
    /// Name of the package file.
    #[arg(long)]
    package_name: String,

    /// ID of the car to package a feature for.
    #[arg(long)]
    car_id: u32,

    /// Feature number to create a package for.
    #[arg(long)]
    feature_number: u32,
}

fn main() {
    let args = Args::parse();

    // Open the package file for writing.
    let mut package_path = PathBuf::from("/package_dir");
    package_path.push(args.package_name);
    let mut package_file = File::create(package_path).unwrap();

    // Open feature signing key.
    let mut signing_key_file = File::open("/secrets/FEATURE_SIGNING_KEY").unwrap();
    let mut signing_key_bytes: Vec<u8> = Vec::new();
    signing_key_file
        .read_to_end(&mut signing_key_bytes)
        .unwrap();
    let signing_key = SigningKey::from_bytes(&signing_key_bytes).unwrap();

    let packaged_feature = PackagedFeatureUnsigned {
        car_id: args.car_id,
        feature_number: args.feature_number,
    };

    let signature: Signature = signing_key.sign(&to_allocvec(&packaged_feature).unwrap());

    let packaged_feature_signed = PackagedFeatureSigned {
        packaged_feature,
        signature: &signature.to_der().to_bytes(),
    };

    package_file
        .write_all(&to_allocvec(&packaged_feature_signed).unwrap())
        .unwrap();
}
