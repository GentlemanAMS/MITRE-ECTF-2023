use crate::MAX_MESSAGE_SIZE;
use core::{mem, time::Duration};
use ucsc_ectf_util_no_std::{
    communication::{CommunicationError, RxChannel, TxChannel},
    eeprom::{
        EepromReadWriteField, BYTE_FIELD_SIZE, CAR_ID_SIZE, PAIRING_PIN_SIZE, SECRET_SIZE,
        SIGNATURE_SIZE,
    },
    messages::{
        Nonce, PairingChallenge, PairingChallengeResponse, PairingPin, PairingRequest, Uart1Message,
    },
    timer::Timer,
    Runtime,
};
use zeroize::Zeroize;

/// Generates a sends a challenge message.
fn generate_and_send_challenge(rt: &mut Runtime, request_nonce: Nonce) -> Option<Nonce> {
    let mut challenge = [0; mem::size_of::<Nonce>()];
    rt.fill_rand_slice(&mut challenge);

    // Send pairing challenge.
    let challenge_msg = Uart1Message::PairingChallenge(PairingChallenge {
        request_nonce,
        challenge,
    });

    let mut buff = [0; MAX_MESSAGE_SIZE];

    match rt.uart1_controller.send(
        postcard::to_slice(&challenge_msg, &mut buff)
            .expect("Failed to serialize pairing challenge."),
    ) {
        Ok(_) => (),
        Err(CommunicationError::InternalError) => {
            panic!("Failed to send pairing challenge (internal error).")
        }
        Err(_) => return None,
    }

    Some(challenge)
}

/// Receives a pairing challenge response message. Inlined to prevent moving of the
/// [`PairingChallengeResponse`].
#[inline(always)]
fn recv_challenge_response(rt: &mut Runtime) -> Option<PairingChallengeResponse> {
    let mut response_bytes = [0; MAX_MESSAGE_SIZE];
    let mut timeout_timer = rt.hib_controller.create_timer(Duration::from_secs(1));

    let challenge_response_msg = loop {
        // Zeroize from previous iteration.
        response_bytes.zeroize();

        // Make sure timer hasn't expired on this iteration first.
        if timeout_timer.poll() {
            return None;
        }

        let size_read = match rt
            .uart1_controller
            .recv_with_timeout(&mut response_bytes, &mut timeout_timer)
        {
            Ok(size_read) => size_read,
            Err(CommunicationError::InternalError) => {
                panic!("Failed to receive unlock challenge response (internal error).")
            }
            Err(_) => {
                continue;
            }
        };

        if let Ok(Uart1Message::PairingChallengeResponse(challenge_response)) =
            postcard::from_bytes::<Uart1Message>(&response_bytes[..size_read])
        {
            break challenge_response;
        } else {
            continue;
        }
    };

    response_bytes.zeroize();

    Some(challenge_response_msg)
}

/// Processes a pairing request, sends a pairing challenge, and receives a pairing challenge
/// response. Verifies the response and returns the verified pairing information. Inlined to
/// prevent moving of the pairing information.
#[inline(always)]
fn unpaired_recv_verified_pairing_info(rt: &mut Runtime) -> Option<PairingChallengeResponse> {
    // Receive pairing request.
    let mut receive_buffer = [0; MAX_MESSAGE_SIZE];

    let size_read = match rt.uart1_controller.recv_with_data_timeout(
        &mut receive_buffer,
        &mut rt.hib_controller.create_timer(Duration::from_secs(5)),
    ) {
        Ok(size_read) => size_read,
        Err(CommunicationError::InternalError) => {
            panic!("Failed to receive pairing request message (internal error).")
        }
        Err(_) => return None,
    };

    let pairing_request = match postcard::from_bytes::<Uart1Message>(&receive_buffer[..size_read]) {
        Ok(Uart1Message::PairingRequest(pairing_request)) => pairing_request,
        _ => return None,
    };

    let request_nonce = pairing_request.0;

    // Generate challenge.
    let challenge = generate_and_send_challenge(rt, request_nonce)?;

    // Wait for challenge response.
    let challenge_response_msg = recv_challenge_response(rt)?;

    // Check nonces.
    if challenge_response_msg.request_nonce != request_nonce
        || challenge_response_msg.challenge_response != challenge
    {
        return None;
    }

    Some(challenge_response_msg)
}

/// Updates the EEPROM with the pairing challenge response information.
fn turn_unpaired_to_paired(rt: &mut Runtime, challenge_response_msg: &PairingChallengeResponse) {
    const ZEROED_SECRET: [u8; SECRET_SIZE] = [0u8; SECRET_SIZE];
    const ZEROED_SIGNATURE: [u8; SIGNATURE_SIZE] = [0u8; SIGNATURE_SIZE];

    rt.eeprom_controller
        .write_slice(
            EepromReadWriteField::UnpairedFobPairingSigningKey,
            &ZEROED_SECRET,
        )
        .expect("EEPROM write failed: unpaired fob pairing signing key.");

    rt.eeprom_controller
        .write_slice(
            EepromReadWriteField::UnpairedFobPairingPublicKeySignature,
            &ZEROED_SIGNATURE,
        )
        .expect("EEPROM write failed: unpaired fob pairing public key signature.");

    rt.eeprom_controller
        .write_slice(
            EepromReadWriteField::KeyFobEncryptionKey,
            &challenge_response_msg.key_fob_encryption_key,
        )
        .expect("EEPROM write failed: key fob encryption key.");

    rt.eeprom_controller
        .write_slice(
            EepromReadWriteField::CarEncryptionKey,
            &challenge_response_msg.car_encryption_key,
        )
        .expect("EEPROM write failed: car encryption key.");

    rt.eeprom_controller
        .write_slice(
            EepromReadWriteField::CarId,
            &challenge_response_msg.car_id.to_be_bytes(),
        )
        .expect("EEPROM write failed: car ID.");

    rt.eeprom_controller
        .write_slice(
            EepromReadWriteField::PairingPin,
            &challenge_response_msg.pairing_pin.0.to_be_bytes(),
        )
        .expect("EEPROM write failed: pairing PIN.");

    let pairing_byte = [1u8; BYTE_FIELD_SIZE];
    rt.eeprom_controller
        .write_slice(EepromReadWriteField::PairingByte, &pairing_byte)
        .expect("EEPROM write failed: pairing byte.");
}

// Pairs an unpaired key fob from self. Requires a secure UART1 channel.
pub(crate) fn run_unpaired(rt: &mut Runtime) -> bool {
    // Receive verified pairing information.
    let challenge_response_msg = match unpaired_recv_verified_pairing_info(rt) {
        Some(challenge_response_msg) => challenge_response_msg,
        None => return false,
    };

    // Set EEPROM fields.
    turn_unpaired_to_paired(rt, &challenge_response_msg);

    true
}

// Generates a challenge response message. Inlined to prevent moving of sensitive data.
#[inline(always)]
fn generate_challenge_response_msg(
    rt: &mut Runtime,
    request_nonce: Nonce,
    challenge_response: Nonce,
) -> PairingChallengeResponse {
    let mut key_fob_encryption_key_bytes = [0; SECRET_SIZE];
    rt.eeprom_controller
        .read_slice(
            EepromReadWriteField::KeyFobEncryptionKey,
            &mut key_fob_encryption_key_bytes,
        )
        .expect("EEPROM read failed: key fob encryption key.");
    let key_fob_encryption_key = key_fob_encryption_key_bytes.into();
    key_fob_encryption_key_bytes.zeroize();

    let mut car_encryption_key_bytes = [0; SECRET_SIZE];
    rt.eeprom_controller
        .read_slice(
            EepromReadWriteField::CarEncryptionKey,
            &mut car_encryption_key_bytes,
        )
        .expect("EEPROM read failed: car encryption key.");
    let car_encryption_key = car_encryption_key_bytes.into();
    car_encryption_key_bytes.zeroize();

    let mut car_id_bytes = [0; CAR_ID_SIZE];
    rt.eeprom_controller
        .read_slice(EepromReadWriteField::CarId, &mut car_id_bytes)
        .expect("EEPROM read failed: car ID.");
    let car_id = u32::from_be_bytes(car_id_bytes);

    let mut pairing_pin_bytes = [0; PAIRING_PIN_SIZE];
    rt.eeprom_controller
        .read_slice(EepromReadWriteField::PairingPin, &mut pairing_pin_bytes)
        .expect("EEPROM read failed: pairing PIN.");
    let pairing_pin = PairingPin(u32::from_be_bytes(pairing_pin_bytes));
    pairing_pin_bytes.zeroize();

    PairingChallengeResponse {
        request_nonce,
        challenge_response,
        key_fob_encryption_key,
        car_encryption_key,
        car_id,
        pairing_pin,
    }
}

// Pairs an unpaired key fob from a paired key fob. Requires a secure UART1 channel.
pub(crate) fn run_paired(rt: &mut Runtime) {
    // Generate request nonce.
    let mut request_nonce = [0; mem::size_of::<Nonce>()];
    rt.fill_rand_slice(&mut request_nonce);

    // Send pairing request.
    let pairing_request = Uart1Message::PairingRequest(PairingRequest(request_nonce));
    let mut buff = [0; MAX_MESSAGE_SIZE];

    match rt.uart1_controller.send(
        postcard::to_slice(&pairing_request, &mut buff)
            .expect("Failed to serialize pairing request."),
    ) {
        Ok(_) => (),
        Err(CommunicationError::InternalError) => {
            panic!("Failed to send pairing request (internal error).")
        }
        Err(_) => return,
    }

    // Receive pairing challenge.
    let mut challenge_bytes = [0; MAX_MESSAGE_SIZE];
    let mut timeout_timer = rt.hib_controller.create_timer(Duration::from_secs(1));

    let challenge_msg = loop {
        // Make sure timer hasn't expired on this iteration first.
        if timeout_timer.poll() {
            return;
        }

        let size_read = match rt
            .uart1_controller
            .recv_with_data_timeout(&mut challenge_bytes, &mut timeout_timer)
        {
            Ok(size_read) => size_read,
            Err(CommunicationError::InternalError) => {
                panic!("Failed to receive pairing challenge (internal error).")
            }
            Err(_) => continue,
        };

        if let Ok(Uart1Message::PairingChallenge(challenge)) =
            postcard::from_bytes::<Uart1Message>(&challenge_bytes[..size_read])
        {
            break challenge;
        } else {
            continue;
        }
    };

    // Verify nonce.
    if challenge_msg.request_nonce != request_nonce {
        return;
    }

    // Generate challenge response message.
    let challenge_response =
        generate_challenge_response_msg(rt, request_nonce, challenge_msg.challenge);
    let challenge_response_msg = Uart1Message::PairingChallengeResponse(challenge_response);

    // Send challenge response.
    let mut buff = [0; MAX_MESSAGE_SIZE];

    if let Err(CommunicationError::InternalError) = rt.uart1_controller.send(
        postcard::to_slice(&challenge_response_msg, &mut buff)
            .expect("Failed to serialize pairing challenge response message."),
    ) {
        panic!("Failed to send pairing challenge response message (internal error).")
    };
}
