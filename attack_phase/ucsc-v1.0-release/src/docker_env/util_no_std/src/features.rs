//! This module provides a function for verifying signed packaged features.

use crate::eeprom::EepromController;
use k256::{
    ecdsa::{signature::Verifier, Signature, VerifyingKey},
    pkcs8::DecodePublicKey,
};
use ucsc_ectf_eeprom_layout::{
    EepromReadOnlyField, EepromReadWriteField, CAR_ID_SIZE, PUBLIC_KEY_SIZE,
};
use ucsc_ectf_util_common::messages::PackagedFeatureSigned;

/// Verifies the signature of a [`PackagedFeatureSigned`] and checks the car
/// ID and feature number associated with it. This function should not be
/// called on an unpaired key fob.
pub fn verify_packaged_feature_signed<'a>(
    eeprom_controller: &mut EepromController,
    packaged_feature_signed: &'a PackagedFeatureSigned<'a>,
) -> bool {
    // Get the packaged feature and signature.
    let packaged_feature = &packaged_feature_signed.packaged_feature;
    let Ok(signature) = Signature::from_der(packaged_feature_signed.signature) else {
        return false;
    };

    // Read the feature verifying key from EEPROM.
    let mut verifying_key_bytes = [0; PUBLIC_KEY_SIZE];
    eeprom_controller
        .read_slice(
            EepromReadOnlyField::FeatureVerifyingKey,
            &mut verifying_key_bytes,
        )
        .expect("EEPROM read failed: feature verifying key.");
    let verifying_key = VerifyingKey::from_public_key_der(
        &verifying_key_bytes[1..verifying_key_bytes[0] as usize + 1],
    )
    .expect("Failed to deserialize feature verifying key.");

    // Verify the signature.
    let mut packaged_feature_buf = [0; 16];
    let packaged_feature_bytes = postcard::to_slice(&packaged_feature, &mut packaged_feature_buf)
        .expect("Failed to serialize packaged feature.");

    if verifying_key
        .verify(packaged_feature_bytes, &signature)
        .is_err()
    {
        return false;
    }

    // Check that the car ID matches the car ID in the packaged feature.
    let car_id = {
        let mut buf = [0; CAR_ID_SIZE];
        eeprom_controller
            .read_slice(EepromReadWriteField::CarId, &mut buf)
            .expect("EEPROM read failed: car ID.");
        u32::from_be_bytes(buf)
    };

    if car_id != packaged_feature.car_id {
        return false;
    }

    matches!(packaged_feature.feature_number, 1..=3)
}
