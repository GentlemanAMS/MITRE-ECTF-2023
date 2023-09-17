use crate::{eeprom_messages, MAX_MESSAGE_SIZE};
use core::{mem, time::Duration};
use ucsc_ectf_util_no_std::{
    communication::{CommunicationError, RxChannel, TxChannel},
    eeprom::{EepromReadWriteField, CAR_ID_SIZE, MESSAGE_SIZE},
    features,
    messages::{
        heapless::Vec, Nonce, Uart0Message, Uart1Message, UnlockChallenge, UnlockChallengeResponse,
        UnlockMessage,
    },
    timer::Timer,
    Runtime,
};

/// Unlocks the car.
fn unlock_car(rt: &mut Runtime, challenge_response: &UnlockChallengeResponse) {
    let unlock_msg_bytes = eeprom_messages::get_unlock_message(&mut rt.eeprom_controller);
    let mut feature_nums = Vec::new();
    let mut feature_msgs_bytes: Vec<[u8; MESSAGE_SIZE], 3> = Vec::new();

    for feature in challenge_response.features.iter() {
        // Verify feature.
        if !features::verify_packaged_feature_signed(&mut rt.eeprom_controller, feature) {
            return;
        }

        // Push feature number.
        feature_nums
            .push(feature.packaged_feature.feature_number)
            .expect("Failed to push feature number.");

        // Push feature message.
        let Some(feature_msg_bytes) = eeprom_messages::get_feature_message(
                &mut rt.eeprom_controller,
                feature.packaged_feature.feature_number,
            ) else {
                return;
            };

        feature_msgs_bytes
            .push(feature_msg_bytes)
            .expect("Failed to push feature message.");
    }

    let host_unlock_msg = Uart0Message::HostUnlock(UnlockMessage {
        unlock_msg: &unlock_msg_bytes,
        feature_nums,
        feature_msgs: feature_msgs_bytes
            .iter()
            .map(|feature| feature.as_slice())
            .collect(),
        car_id: challenge_response.car_id,
    });

    let mut host_unlock_msg_buff = [0; MAX_MESSAGE_SIZE];

    if let Err(CommunicationError::InternalError) = rt.uart0_controller.send(
        postcard::to_slice(&host_unlock_msg, &mut host_unlock_msg_buff)
            .expect("Failed to serialize host unlock message."),
    ) {
        panic!("Failed to send host unlock message (internal error).");
    }
}

pub(crate) fn process_msg(rt: &mut Runtime, receive_msg: &Uart1Message) {
    let unlock_request = match receive_msg {
        Uart1Message::UnlockRequest(msg) => msg,
        _ => return,
    };

    // Get car ID from EEPROM.
    let mut car_id_bytes = [0; CAR_ID_SIZE];
    rt.eeprom_controller
        .read_slice(EepromReadWriteField::CarId, &mut car_id_bytes)
        .expect("EEPROM read failed: car ID.");
    let car_id = u32::from_be_bytes(car_id_bytes);

    // Verify car ID.
    if unlock_request.0 != car_id {
        return;
    }

    // Generate challenge.
    let mut challenge = [0; mem::size_of::<Nonce>()];
    rt.fill_rand_slice(&mut challenge);

    // Send challenge.
    let challenge_msg = Uart1Message::UnlockChallenge(UnlockChallenge { car_id, challenge });
    let mut challenge_msg_buff = [0; MAX_MESSAGE_SIZE];

    match rt.uart1_controller.send(
        postcard::to_slice(&challenge_msg, &mut challenge_msg_buff)
            .expect("Failed to serialize unlock challenge."),
    ) {
        Ok(_) => (),
        Err(CommunicationError::InternalError) => {
            panic!("Failed to send unlock challenge (internal error).")
        }
        Err(_) => return,
    }

    // Wait for challenge response.
    let mut response_bytes = [0; MAX_MESSAGE_SIZE];
    let mut timeout_timer = rt.hib_controller.create_timer(Duration::from_secs(1));

    let challenge_response = loop {
        // Make sure timer hasn't expired on this iteration first.
        if timeout_timer.poll() {
            return;
        }

        let size_read = match rt
            .uart1_controller
            .recv_with_timeout(&mut response_bytes, &mut timeout_timer)
        {
            Ok(size_read) => size_read,
            Err(CommunicationError::InternalError) => {
                panic!("Failed to receive unlock challenge response (internal error).")
            }
            Err(_) => return,
        };

        if let Ok(Uart1Message::UnlockChallengeResponse(challenge_response)) =
            postcard::from_bytes::<Uart1Message>(&response_bytes[..size_read])
        {
            break challenge_response;
        }
    };

    // Verify car ID.
    if challenge_response.car_id != car_id {
        return;
    }

    // Verify challenge.
    if challenge_response.challenge_response != challenge {
        return;
    }

    // Unlock car.
    unlock_car(rt, &challenge_response);
}
