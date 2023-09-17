use ucsc_ectf_util_no_std::{
    eeprom::{EepromController, EepromReadOnlyField, MESSAGE_SIZE},
    messages::FeatureNumber,
};

/// Get the unlock message from the EEPROM.
pub(crate) fn get_unlock_message(eeprom_controller: &mut EepromController) -> [u8; MESSAGE_SIZE] {
    let mut unlock_msg_bytes = [0; MESSAGE_SIZE];
    eeprom_controller
        .read_slice(EepromReadOnlyField::UnlockMessage, &mut unlock_msg_bytes)
        .expect("EEPROM read failed: unlock message.");

    unlock_msg_bytes
}

/// Get a feature message from the EEPROM.
///
/// Returns [`None`] if the feature number is invalid.
pub(crate) fn get_feature_message(
    eeprom_controller: &mut EepromController,
    feature: FeatureNumber,
) -> Option<[u8; MESSAGE_SIZE]> {
    let mut feature_msg_bytes = [0; MESSAGE_SIZE];

    let feature_msg_type = match feature {
        1 => EepromReadOnlyField::FeatureOneMessage,
        2 => EepromReadOnlyField::FeatureTwoMessage,
        3 => EepromReadOnlyField::FeatureThreeMessage,
        _ => return None,
    };

    eeprom_controller
        .read_slice(feature_msg_type, &mut feature_msg_bytes)
        .expect("EEPROM read failed: feature message.");

    Some(feature_msg_bytes)
}
