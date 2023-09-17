use std::env;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use hex::decode;
use k256::ecdsa::{signature::Signer, Signature, SigningKey};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::pkcs8::EncodePublicKey;
use k256::SecretKey;
use ucsc_ectf_eeprom_layout::{
    EepromReadField, EepromReadOnlyField, EepromReadWriteField, BYTE_FIELD_SIZE, SECRET_SIZE,
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
        let mut pairing_manufacturer_paired_fob_signing_key_file = File::open(format!(
            "{secrets_dir}/PAIRING_MANUFACTURER_PAIRED_FOB_SIGNING_KEY"
        ))
        .unwrap();
        let mut pairing_manufacturer_paired_fob_verifying_key_file = OpenOptions::new()
            .write(true)
            .create(false)
            .truncate(false)
            .append(false)
            .open(format!(
                "{secrets_dir}/PAIRING_MANUFACTURER_PAIRED_FOB_VERIFYING_KEY"
            ))
            .unwrap();

        let mut pairing_manufacturer_unpaired_fob_signing_key_file = File::open(format!(
            "{secrets_dir}/PAIRING_MANUFACTURER_UNPAIRED_FOB_SIGNING_KEY"
        ))
        .unwrap();
        let mut pairing_manufacturer_unpaired_fob_verifying_key_file = OpenOptions::new()
            .write(true)
            .create(false)
            .truncate(false)
            .append(false)
            .open(format!(
                "{secrets_dir}/PAIRING_MANUFACTURER_UNPAIRED_FOB_VERIFYING_KEY"
            ))
            .unwrap();

        let mut paired_fob_pairing_signing_key_file =
            File::open(format!("{secrets_dir}/PAIRED_FOB_PAIRING_SIGNING_KEY")).unwrap();
        let mut paired_fob_pairing_public_key_signature_file = File::create(format!(
            "{secrets_dir}/PAIRED_FOB_PAIRING_PUBLIC_KEY_SIGNATURE"
        ))
        .unwrap();

        let mut unpaired_fob_pairing_signing_key_file =
            File::open(format!("{secrets_dir}/UNPAIRED_FOB_PAIRING_SIGNING_KEY")).unwrap();
        let mut unpaired_fob_pairing_public_key_signature_file = File::create(format!(
            "{secrets_dir}/UNPAIRED_FOB_PAIRING_PUBLIC_KEY_SIGNATURE"
        ))
        .unwrap();

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

        let mut private_key_bytes = [0u8; 32];

        pairing_manufacturer_paired_fob_signing_key_file
            .read_exact(&mut private_key_bytes)
            .unwrap();
        let pairing_manufacturer_paired_fob_signing_key =
            SigningKey::from_bytes(&private_key_bytes).unwrap();
        let pairing_manufacturer_paired_fob_verifying_key =
            pairing_manufacturer_paired_fob_signing_key.verifying_key();
        let mut pairing_manufacturer_paired_fob_verifying_key_bytes =
            pairing_manufacturer_paired_fob_verifying_key
                .to_public_key_der()
                .unwrap()
                .into_vec();
        pairing_manufacturer_paired_fob_verifying_key_bytes.insert(
            0,
            pairing_manufacturer_paired_fob_verifying_key_bytes.len() as u8,
        );
        pairing_manufacturer_paired_fob_verifying_key_file
            .write_all(&pairing_manufacturer_paired_fob_verifying_key_bytes)
            .unwrap();

        pairing_manufacturer_unpaired_fob_signing_key_file
            .read_exact(&mut private_key_bytes)
            .unwrap();
        let pairing_manufacturer_unpaired_fob_signing_key =
            SigningKey::from_bytes(&private_key_bytes).unwrap();
        let pairing_manufacturer_unpaired_fob_verifying_key =
            pairing_manufacturer_unpaired_fob_signing_key.verifying_key();
        let mut pairing_manufacturer_unpaired_fob_verifying_key_bytes =
            pairing_manufacturer_unpaired_fob_verifying_key
                .to_public_key_der()
                .unwrap()
                .into_vec();
        pairing_manufacturer_unpaired_fob_verifying_key_bytes.insert(
            0,
            pairing_manufacturer_unpaired_fob_verifying_key_bytes.len() as u8,
        );
        pairing_manufacturer_unpaired_fob_verifying_key_file
            .write_all(&pairing_manufacturer_unpaired_fob_verifying_key_bytes)
            .unwrap();

        paired_fob_pairing_signing_key_file
            .read_exact(&mut private_key_bytes)
            .unwrap();
        let paired_fob_pairing_signing_key = SecretKey::from_be_bytes(&private_key_bytes).unwrap();
        let paired_fob_pairing_verifying_key = paired_fob_pairing_signing_key.public_key();

        let paired_fob_pairing_public_key_signature: Signature =
            pairing_manufacturer_paired_fob_signing_key.sign(
                paired_fob_pairing_verifying_key
                    .to_encoded_point(true)
                    .as_bytes(),
            );
        paired_fob_pairing_public_key_signature_file
            .write_all(&paired_fob_pairing_public_key_signature.to_bytes())
            .unwrap();

        unpaired_fob_pairing_signing_key_file
            .read_exact(&mut private_key_bytes)
            .unwrap();
        let unpaired_fob_pairing_signing_key =
            SecretKey::from_be_bytes(&private_key_bytes).unwrap();
        let unpaired_fob_pairing_verifying_key = unpaired_fob_pairing_signing_key.public_key();

        let unpaired_fob_pairing_public_key_signature: Signature =
            pairing_manufacturer_unpaired_fob_signing_key.sign(
                unpaired_fob_pairing_verifying_key
                    .to_encoded_point(true)
                    .as_bytes(),
            );
        unpaired_fob_pairing_public_key_signature_file
            .write_all(&unpaired_fob_pairing_public_key_signature.to_bytes())
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
            EepromReadOnlyField::PairedFobPairingSigningKey,
            format!("{secrets_dir}/PAIRED_FOB_PAIRING_SIGNING_KEY"),
        );

        eeprom_field_from_path(
            &mut eeprom_file,
            EepromReadOnlyField::PairedFobPairingPublicKeySignature,
            format!("{secrets_dir}/PAIRED_FOB_PAIRING_PUBLIC_KEY_SIGNATURE"),
        );

        eeprom_field_from_path(
            &mut eeprom_file,
            EepromReadOnlyField::PairingManufacturerPairedFobVerifyingKey,
            format!("{secrets_dir}/PAIRING_MANUFACTURER_PAIRED_FOB_VERIFYING_KEY"),
        );

        eeprom_field_from_path(
            &mut eeprom_file,
            EepromReadOnlyField::PairingManufacturerUnpairedFobVerifyingKey,
            format!("{secrets_dir}/PAIRING_MANUFACTURER_UNPAIRED_FOB_VERIFYING_KEY"),
        );

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

        // Is paired key fob.
        if let (Some(car_id), Some(pairing_pin)) = (option_env!("CAR_ID"), option_env!("PAIR_PIN"))
        {
            let buf: u32 = car_id.parse().unwrap();
            eeprom_field_from_buf(
                &mut eeprom_file,
                EepromReadWriteField::CarId,
                &buf.to_be_bytes(),
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

            let buf = decode(pairing_pin).unwrap();
            eeprom_field_from_buf(&mut eeprom_file, EepromReadWriteField::PairingPin, &buf);
            eeprom_field_from_buf(
                &mut eeprom_file,
                EepromReadWriteField::PairingByte,
                &[1u8; BYTE_FIELD_SIZE],
            );
        } else {
            // Is unpaired key fob.
            eeprom_field_from_path(
                &mut eeprom_file,
                EepromReadWriteField::UnpairedFobPairingSigningKey,
                format!("{secrets_dir}/UNPAIRED_FOB_PAIRING_SIGNING_KEY"),
            );

            eeprom_field_from_path(
                &mut eeprom_file,
                EepromReadWriteField::UnpairedFobPairingPublicKeySignature,
                format!("{secrets_dir}/UNPAIRED_FOB_PAIRING_PUBLIC_KEY_SIGNATURE"),
            );
        }

        println!("cargo:rerun-if-changed={secrets_dir}");
    }

    // Only re-run the build script when this file, memory.x, or link.x is changed.
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=memory.x");
    println!("cargo:rerun-if-changed=link.x");
}
