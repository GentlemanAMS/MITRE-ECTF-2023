use crate::{features, MAX_MESSAGE_SIZE};
use core::time::Duration;
use ucsc_ectf_util_no_std::{
    communication::{CommunicationError, RxChannel, TxChannel},
    eeprom::{EepromReadWriteField, CAR_ID_SIZE, PACKAGED_FEATURE_SIGNED_SIZE, SECRET_SIZE},
    messages::{
        heapless::Vec, FeatureNumber, Uart1Message, UnlockChallengeResponse, UnlockRequest,
        NUM_FEATURES,
    },
    timer::Timer,
    Runtime,
};
use zeroize::Zeroize;

pub(crate) fn process_button_press(rt: &mut Runtime) {
    // Create timer to debounce the button at the end.
    let mut unlock_timer = rt.hib_controller.create_timer(Duration::from_millis(100));

    // Transmit and receive on UART1 using unlock keys.
    let mut key_fob_encryption_key = [0; SECRET_SIZE];
    let mut car_encryption_key = [0; SECRET_SIZE];

    rt.eeprom_controller
        .read_slice(
            EepromReadWriteField::KeyFobEncryptionKey,
            &mut key_fob_encryption_key,
        )
        .expect("EEPROM read failed: key fob encryption key.");
    rt.eeprom_controller
        .read_slice(
            EepromReadWriteField::CarEncryptionKey,
            &mut car_encryption_key,
        )
        .expect("EEPROM read failed: car encryption key.");

    rt.uart1_controller
        .change_rx_key(&car_encryption_key.into());
    car_encryption_key.zeroize();
    rt.uart1_controller
        .change_tx_key(&key_fob_encryption_key.into());
    key_fob_encryption_key.zeroize();

    // Get car ID from EEPROM.
    let mut car_id_bytes = [0; CAR_ID_SIZE];
    rt.eeprom_controller
        .read_slice(EepromReadWriteField::CarId, &mut car_id_bytes)
        .expect("EEPROM read failed: car ID.");
    let car_id = u32::from_be_bytes(car_id_bytes);

    // Send unlock request to car.
    let unlock_request = Uart1Message::UnlockRequest(UnlockRequest(car_id));
    let mut unlock_request_buff = [0; MAX_MESSAGE_SIZE];

    match rt.uart1_controller.send(
        postcard::to_slice(&unlock_request, &mut unlock_request_buff)
            .expect("Failed to serialize unlock request."),
    ) {
        Ok(_) => (),
        Err(CommunicationError::InternalError) => {
            panic!("Failed to send unlock request (internal error).")
        }
        Err(_) => return,
    }

    // Wait for challenge.
    let mut challenge_bytes = [0; MAX_MESSAGE_SIZE];
    let mut timeout_timer = rt.hib_controller.create_timer(Duration::from_secs(1));

    let challenge = loop {
        // Make sure timer hasn't expired on this iteration first.
        if timeout_timer.poll() {
            return;
        }

        let size_read = match rt
            .uart1_controller
            .recv_with_timeout(&mut challenge_bytes, &mut timeout_timer)
        {
            Ok(size_read) => size_read,
            Err(CommunicationError::InternalError) => {
                panic!("Failed to receive unlock challenge (internal error).")
            }
            Err(_) => return,
        };

        if let Ok(Uart1Message::UnlockChallenge(msg)) =
            postcard::from_bytes::<Uart1Message>(&challenge_bytes[..size_read])
        {
            break msg;
        }
    };

    // Verify car ID.
    if challenge.car_id != car_id {
        return;
    }

    // Grab features.
    let mut features_bytes = [[0; PACKAGED_FEATURE_SIGNED_SIZE]; NUM_FEATURES];
    let mut features = Vec::new();

    for (i, feature) in features_bytes.iter_mut().enumerate() {
        if let Some(packaged_feature_signed) = features::get_installed_feature(
            &mut rt.eeprom_controller,
            (i + 1) as FeatureNumber,
            feature,
        ) {
            features
                .push(packaged_feature_signed)
                .expect("Failed to push feature to UnlockChallengeResponse feature vec.");
        }
    }

    // Send challenge response.
    let challenge_response_msg = Uart1Message::UnlockChallengeResponse(UnlockChallengeResponse {
        car_id,
        challenge_response: challenge.challenge,
        features,
    });
    let mut challenge_response_msg_buff = [0; MAX_MESSAGE_SIZE];

    if let Err(CommunicationError::InternalError) = rt.uart1_controller.send(
        postcard::to_slice(&challenge_response_msg, &mut challenge_response_msg_buff)
            .expect("Failed to serialize unlock challenge response."),
    ) {
        panic!("Failed to send unlock challenge response (internal error).")
    }

    // Spin while unlock timer has not expired. This is because the button controller does not
    // debounce, so the timer will act as a cooldown, effectively debouncing the button.
    while !unlock_timer.poll() {}
}
