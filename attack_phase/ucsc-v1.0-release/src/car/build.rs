use std::env;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use k256::ecdsa::SigningKey;
use k256::pkcs8::EncodePublicKey;
use ucsc_ectf_eeprom_layout::{
    EepromReadField, EepromReadOnlyField, EepromReadWriteField, SECRET_SIZE,
};

fn eeprom_field_from_path<P, F>(eeprom_file: &mut File, field: F, path: P)
where
    P: AsRef<Path>,
    F: EepromReadField,
{
    let mut f = File::open(path).unwrap();
    let bounds = EepromReadField::get_field_bounds(&field);
    let offset = bounds.address as u64;
    let mut buf = vec![0u8; bounds.size];
    f.read_exact(&mut buf).unwrap();
    eeprom_file.seek(SeekFrom::Start(offset)).unwrap();
    eeprom_file.write_all(&buf).unwrap();
}

fn eeprom_field_from_buf<F>(eeprom_file: &mut File, field: F, buf: &[u8])
where
    F: EepromReadField,
{
    let bounds = EepromReadField::get_field_bounds(&field);
    let offset = bounds.address as u64;
    eeprom_file.seek(SeekFrom::Start(offset)).unwrap();
    eeprom_file.write_all(buf).unwrap();
}

fn main() {
    // Get the out directory.
    let out = &PathBuf::from(env::var_os("OUT_DIR").unwrap());

    // Add out directory to the linker search path.
    println!("cargo:rustc-link-search={}", out.display());

    // Put the memory.x linker script somewhere the linker can find it.
    File::create(out.join("memory.x"))
        .unwrap()
        .write_all(include_bytes!("memory.x"))
        .unwrap();

    // Put the link.x linker script somewhere the linker can find it.
    File::create(out.join("link.x"))
        .unwrap()
        .write_all(include_bytes!("link.x"))
        .unwrap();

    if let Some(secrets_dir) = option_env!("SECRETS_DIR") {
        let mut feature_signing_key_file =
            File::open(format!("{secrets_dir}/FEATURE_SIGNING_KEY")).unwrap();
        let mut feature_verifying_key_file = OpenOptions::new()
            .write(true)
            .create(false)
            .truncate(false)
            .append(false)
            .open(format!("{secrets_dir}/FEATURE_VERIFYING_KEY"))
            .unwrap();
        let mut eeprom_file = OpenOptions::new()
            .write(true)
            .create(false)
            .truncate(false)
            .append(false)
            .open(option_env!("EEPROM_PATH").unwrap())
            .unwrap();

        let mut feature_signing_key_bytes = [0u8; SECRET_SIZE];
        feature_signing_key_file
            .read_exact(&mut feature_signing_key_bytes)
            .unwrap();
        let feature_signing_key = SigningKey::from_bytes(&feature_signing_key_bytes).unwrap();
        let feature_verifying_key = feature_signing_key.verifying_key();
        let mut feature_verifying_key_bytes = feature_verifying_key
            .to_public_key_der()
            .unwrap()
            .into_vec();
        feature_verifying_key_bytes.insert(0, feature_verifying_key_bytes.len() as u8);
        feature_verifying_key_file
            .write_all(&feature_verifying_key_bytes)
            .unwrap();

        eeprom_field_from_path(
            &mut eeprom_file,
            EepromReadOnlyField::FeatureVerifyingKey,
            format!("{secrets_dir}/FEATURE_VERIFYING_KEY"),
        );

        eeprom_field_from_path(
            &mut eeprom_file,
            EepromReadOnlyField::SecretSeed,
            format!("{secrets_dir}/SECRET_SEED"),
        );

        eeprom_field_from_path(
            &mut eeprom_file,
            EepromReadWriteField::KeyFobEncryptionKey,
            format!("{secrets_dir}/UNLOCK_KEY_ONE"),
        );

        eeprom_field_from_path(
            &mut eeprom_file,
            EepromReadWriteField::CarEncryptionKey,
            format!("{secrets_dir}/UNLOCK_KEY_TWO"),
        );

        let car_id = option_env!("CAR_ID").unwrap();
        let buf: u32 = car_id.parse::<u32>().unwrap();
        eeprom_field_from_buf(
            &mut eeprom_file,
            EepromReadWriteField::CarId,
            &buf.to_be_bytes(),
        );

        println!("cargo:rerun-if-changed={secrets_dir}");
    }

    // Only re-run the build script when this file, memory.x, or link.x is changed.
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=memory.x");
    println!("cargo:rerun-if-changed=link.x");
}
