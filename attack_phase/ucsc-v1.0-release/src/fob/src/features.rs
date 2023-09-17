use crate::MAX_MESSAGE_SIZE;
use ucsc_ectf_util_no_std::{
    communication::{CommunicationError, TxChannel},
    eeprom::{EepromController, EepromReadWriteField, PACKAGED_FEATURE_SIGNED_SIZE},
    features::verify_packaged_feature_signed,
    messages::{FeatureNumber, HostToolAck, PackagedFeatureSigned, Uart0Message},
    Runtime,
};

/// Gets the feature with the given feature number if it is installed. The slice is used to store
/// the [`PackagedFeatureSigned`] in serialized form, which will be used by the returned
/// [`PackagedFeatureSigned`]. This function should not be called on an unpaired key fob.
pub(crate) fn get_installed_feature<'a>(
    eeprom_controller: &mut EepromController,
    feature: FeatureNumber,
    buf: &'a mut [u8; PACKAGED_FEATURE_SIGNED_SIZE],
) -> Option<PackagedFeatureSigned<'a>> {
    let feature_eeprom_field = match feature {
        1 => EepromReadWriteField::FeatureOneSignedPackaged,
        2 => EepromReadWriteField::FeatureTwoSignedPackaged,
        3 => EepromReadWriteField::FeatureThreeSignedPackaged,
        _ => return None,
    };

    // Read the appropriate signed packaged feature field from EEPROM.
    eeprom_controller
        .read_slice(feature_eeprom_field, buf)
        .expect("EEPROM read failed: signed packaged feature.");

    let packaged_feature_signed = postcard::from_bytes::<PackagedFeatureSigned>(buf).ok()?;

    // Verify the signed packaged feature.
    verify_packaged_feature_signed(eeprom_controller, &packaged_feature_signed)
        .then_some(packaged_feature_signed)
}

fn send_ack(rt: &mut Runtime, status: bool) {
    let mut buf = [0; MAX_MESSAGE_SIZE];
    let res = postcard::to_slice(
        &Uart0Message::EnableFeatureResponse(HostToolAck(status)),
        &mut buf,
    )
    .expect("Failed to serialize enable feature response.");

    if let Err(CommunicationError::InternalError) = rt.uart0_controller.send(res) {
        panic!("Failed to send enable feature response (internal error).");
    }
}

pub(crate) fn paired_process_msg(rt: &mut Runtime, msg: &Uart0Message) {
    // Check the message type.
    let packaged_feature_signed = match msg {
        Uart0Message::EnableFeatureRequest(msg) => &msg.0,
        _ => return,
    };

    // Verify the signed packaged feature.
    if !verify_packaged_feature_signed(&mut rt.eeprom_controller, packaged_feature_signed) {
        send_ack(rt, false);
        return;
    };

    // Write the signed packaged feature to the appropriate EEPROM field.
    let feature_eeprom_field = match packaged_feature_signed.packaged_feature.feature_number {
        1 => EepromReadWriteField::FeatureOneSignedPackaged,
        2 => EepromReadWriteField::FeatureTwoSignedPackaged,
        3 => EepromReadWriteField::FeatureThreeSignedPackaged,
        _ => {
            send_ack(rt, false);
            return;
        }
    };

    let mut packaged_feature_signed_buf = [0; PACKAGED_FEATURE_SIGNED_SIZE];
    postcard::to_slice(&packaged_feature_signed, &mut packaged_feature_signed_buf)
        .expect("Failed to serialize signed packaged feature.");
    rt.eeprom_controller
        .write_slice(feature_eeprom_field, &packaged_feature_signed_buf)
        .expect("EEPROM write failed: signed packaged feature.");

    send_ack(rt, true);
}
