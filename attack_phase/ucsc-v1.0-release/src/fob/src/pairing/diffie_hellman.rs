use crate::MAX_MESSAGE_SIZE;
use core::time::Duration;
use k256::{
    ecdh,
    ecdsa::{signature::Signer, Signature, SigningKey, VerifyingKey},
    elliptic_curve::sec1::ToEncodedPoint,
    pkcs8::DecodePublicKey,
    sha2::Sha256,
    PublicKey, SecretKey,
};
use ucsc_ectf_util_no_std::{
    communication::{CommunicationError, RxChannel, TxChannel, Uart1Controller},
    eeprom::{
        EepromController, EepromReadOnlyField, EepromReadWriteField, PUBLIC_KEY_SIZE, SECRET_SIZE,
        SIGNATURE_SIZE,
    },
    messages::{DiffieHellmanMessage, Key, Uart1Message, VerifiedPublicKey},
    timer::{HibTimer, Timer},
    Runtime, Uart1RxPin, Uart1TxPin,
};
use zeroize::Zeroize;

/// Waits for up to the expiration of `timeout_timer` to receive and verify an ephemeral public key.
fn recv_verified_ephemeral_public_key(
    uart1_controller: &mut Uart1Controller<Uart1TxPin, Uart1RxPin>,
    eeprom_controller: &mut EepromController,
    timeout_timer: &mut HibTimer,
    paired: bool,
) -> Option<PublicKey> {
    // Loop to ignore any invalid messages.
    loop {
        // Make sure timer hasn't expired.
        if timeout_timer.poll() {
            return None;
        }

        // Receive Diffie-Hellman message on UART1.
        let mut receive_buffer = [0; MAX_MESSAGE_SIZE];

        let size_read =
            match uart1_controller.recv_with_data_timeout(&mut receive_buffer, timeout_timer) {
                Ok(size_read) => size_read,
                Err(CommunicationError::InternalError) => {
                    panic!("Failed to receive Diffie-Hellman message (internal error).")
                }
                Err(_) => continue,
            };

        let msg = match postcard::from_bytes::<Uart1Message>(&receive_buffer[..size_read]) {
            Ok(Uart1Message::DiffieHellman(msg)) => msg,
            _ => continue,
        };

        // Determine which pairing verifying key field to use. Use the verifying key for the other side.
        let manufacturer_pairing_verifying_key_field = if paired {
            EepromReadOnlyField::PairingManufacturerUnpairedFobVerifyingKey
        } else {
            EepromReadOnlyField::PairingManufacturerPairedFobVerifyingKey
        };

        // Get manufacturer pairing verifying key from EEPROM.
        let mut manufacturer_pairing_verifying_key_bytes = [0; PUBLIC_KEY_SIZE];
        eeprom_controller
            .read_slice(
                manufacturer_pairing_verifying_key_field,
                &mut manufacturer_pairing_verifying_key_bytes,
            )
            .expect("EEPROM read failed: manufacturer pairing verifying key.");
        let manufacturer_pairing_verifying_key = VerifyingKey::from_public_key_der(
            &manufacturer_pairing_verifying_key_bytes
                [1..manufacturer_pairing_verifying_key_bytes[0] as usize + 1],
        )
        .expect("Failed to deserialize manufacturer pairing verifying key.");

        // Verify and get key signing public key.
        let Some(key_signing_public_key) = msg
            .key_signing_public_key
            .verify_and_get_key(&manufacturer_pairing_verifying_key)
        else {
            continue;
        };

        // Verify the paired key fob's ephemeral public key.
        if let Some(ephemeral_public_key) = msg
            .ephemeral_public_key
            .verify_and_get_key(&key_signing_public_key.into())
        {
            return Some(ephemeral_public_key);
        } else {
            continue;
        }
    }
}

/// Sends a Diffie-Hellman message.
fn send_diffie_hellman_msg(
    rt: &mut Runtime,
    pairing_public_key: &PublicKey,
    pairing_public_key_signature: &Signature,
    ephemeral_public_key: &PublicKey,
    ephemeral_public_key_signature: &Signature,
) -> bool {
    // Construct Uart1Message.
    let pairing_public_key_encoded = pairing_public_key.to_encoded_point(true);
    let pairing_public_key_signature_bytes = pairing_public_key_signature.to_bytes();
    let ephemeral_public_key_encoded = ephemeral_public_key.to_encoded_point(true);
    let ephemeral_public_key_signature_bytes = ephemeral_public_key_signature.to_bytes();

    let msg = Uart1Message::DiffieHellman(DiffieHellmanMessage {
        key_signing_public_key: VerifiedPublicKey {
            public_key: pairing_public_key_encoded.as_bytes(),
            public_key_signature: &pairing_public_key_signature_bytes,
        },
        ephemeral_public_key: VerifiedPublicKey {
            public_key: ephemeral_public_key_encoded.as_bytes(),
            public_key_signature: &ephemeral_public_key_signature_bytes,
        },
    });

    // Send message.
    let mut buff = [0; MAX_MESSAGE_SIZE];

    match rt.uart1_controller.send(
        postcard::to_slice(&msg, &mut buff).expect("Failed to serialize Diffie-Hellman message."),
    ) {
        Ok(_) => true,
        Err(CommunicationError::InternalError) => {
            panic!("Failed to send Diffie-Hellman message (internal error).")
        }
        Err(_) => false,
    }
}

/// Generates an ephemeral key. Inlined to prevent copying of the private key.
#[inline(always)]
fn generate_ephemeral_key(rt: &mut Runtime) -> SecretKey {
    let mut ephemeral_private_key_bytes = [0; SECRET_SIZE];
    rt.fill_rand_slice(&mut ephemeral_private_key_bytes);
    let ephemeral_private_key = SecretKey::from_be_bytes(&ephemeral_private_key_bytes)
        .expect("Failed to create ephemeral private key.");
    ephemeral_private_key_bytes.zeroize();

    ephemeral_private_key
}

/// Performs the Diffie-Hellman function, and sets the UART1 channel key.
fn diffie_hellman_set_key(
    rt: &mut Runtime,
    paired_ephemeral_public_key: &PublicKey,
    ephemeral_private_key: &SecretKey,
) {
    // Calculate session key.
    let mut ephemeral_private_key_scalar = ephemeral_private_key.to_nonzero_scalar();
    let session_key = ecdh::diffie_hellman(
        &ephemeral_private_key_scalar,
        paired_ephemeral_public_key.as_affine(),
    );
    ephemeral_private_key_scalar.zeroize();

    // Extract session key bytes.
    let mut session_key_bytes = [0; SECRET_SIZE];
    session_key
        .extract::<Sha256>(None)
        .expand(b"", &mut session_key_bytes)
        .expect("Failed to expand session key.");

    // Set key for UART1.
    rt.uart1_controller.change_rx_key(&session_key_bytes.into());
    rt.uart1_controller.change_tx_key(&session_key_bytes.into());
    session_key_bytes.zeroize();
}

/// Signs the ephemeral public key with the pairing private key. Returns the signature and the
/// pairing public key.
fn sign_ephemeral_public_key(
    rt: &mut Runtime,
    paired: bool,
    ephemeral_public_key: &PublicKey,
) -> (Signature, PublicKey) {
    // Get pairing private key from EEPROM.
    let mut pairing_private_key_bytes = [0; SECRET_SIZE];

    if paired {
        rt.eeprom_controller
            .read_slice(
                EepromReadOnlyField::PairedFobPairingSigningKey,
                &mut pairing_private_key_bytes,
            )
            .expect("EEPROM read failed: fob pairing signing key.");
    } else {
        rt.eeprom_controller
            .read_slice(
                EepromReadWriteField::UnpairedFobPairingSigningKey,
                &mut pairing_private_key_bytes,
            )
            .expect("EEPROM read failed: fob pairing signing key.");
    }

    // Sign with pairing private key.
    let pairing_private_key = SecretKey::from_be_bytes(&pairing_private_key_bytes)
        .expect("Failed to deserialize fob pairing signing key.");
    pairing_private_key_bytes.zeroize();
    let pairing_public_key = pairing_private_key.public_key();
    let ephemeral_public_key_signature = SigningKey::from(pairing_private_key)
        .sign(ephemeral_public_key.to_encoded_point(true).as_bytes());

    (ephemeral_public_key_signature, pairing_public_key)
}

/// Gets the pairing public key signature from the EEPROM.
fn get_pairing_public_key_signature(rt: &mut Runtime, paired: bool) -> Signature {
    // Read pairing public key signature from EEPROM.
    let mut pairing_public_key_signature_bytes = [0; SIGNATURE_SIZE];

    if paired {
        rt.eeprom_controller
            .read_slice(
                EepromReadOnlyField::PairedFobPairingPublicKeySignature,
                &mut pairing_public_key_signature_bytes,
            )
            .expect("EEPROM read failed: pairing public key signature.");
    } else {
        rt.eeprom_controller
            .read_slice(
                EepromReadWriteField::UnpairedFobPairingPublicKeySignature,
                &mut pairing_public_key_signature_bytes,
            )
            .expect("EEPROM read failed: pairing public key signature.");
    }

    Signature::try_from(pairing_public_key_signature_bytes.as_slice())
        .expect("Failed to deserialize pairing public key signature.")
}

/// Prepares and sends a Diffie-Hellman message. Inlined to prevent copying of the ephemeral private
/// key.
#[inline(always)]
fn prepare_and_send_diffie_hellman_message(rt: &mut Runtime, paired: bool) -> Option<SecretKey> {
    // Get fields necessary for Diffie-Hellman message.
    let ephemeral_private_key = generate_ephemeral_key(rt);
    let ephemeral_public_key = ephemeral_private_key.public_key();
    let (ephemeral_public_key_signature, pairing_public_key) =
        sign_ephemeral_public_key(rt, paired, &ephemeral_public_key);
    let pairing_public_key_signature = get_pairing_public_key_signature(rt, paired);

    // Send Diffie-Hellman message to unpaired key fob.
    if send_diffie_hellman_msg(
        rt,
        &pairing_public_key,
        &pairing_public_key_signature,
        &ephemeral_public_key,
        &ephemeral_public_key_signature,
    ) {
        Some(ephemeral_private_key)
    } else {
        None
    }
}

/// Performs the Diffie-Hellman key exchange as an unpaired key fob and sets the UART1 channel key.
pub(crate) fn run_unpaired(rt: &mut Runtime) -> bool {
    // Set keys to default. Necessary in case of failure after key exchange.
    let default_key: Key = Default::default();
    rt.uart1_controller.change_rx_key(&default_key);
    rt.uart1_controller.change_tx_key(&default_key);

    // Receive ephemeral public key from paired key fob.
    let Some(paired_ephemeral_public_key) = recv_verified_ephemeral_public_key(
        &mut rt.uart1_controller,
        &mut rt.eeprom_controller,
        &mut rt.hib_controller.create_timer(Duration::from_secs(1000)),
        false,
    ) else {
        return false;
    };

    // Generate ephemeral private key and send Diffie-Hellman message.
    let Some(ephemeral_private_key) = prepare_and_send_diffie_hellman_message(rt, false)
    else {
        return false;
    };

    // Set UART1 channel key.
    diffie_hellman_set_key(rt, &paired_ephemeral_public_key, &ephemeral_private_key);

    true
}

/// Performs the Diffie-Hellman key exchange as a paired key fob and sets the UART1 channel key.
pub(crate) fn run_paired(rt: &mut Runtime) -> bool {
    // Set keys to default. Necessary in case of failure after key exchange.
    let default_key: Key = Default::default();
    rt.uart1_controller.change_rx_key(&default_key);
    rt.uart1_controller.change_tx_key(&default_key);

    // Generate ephemeral private key and send Diffie-Hellman message.
    let Some(ephemeral_private_key) = prepare_and_send_diffie_hellman_message(rt, true)
    else {
        return false;
    };

    // Receive ephemeral public key from unpaired key fob.
    let Some(unpaired_ephemeral_public_key) = recv_verified_ephemeral_public_key(
        &mut rt.uart1_controller,
        &mut rt.eeprom_controller,
        &mut rt.hib_controller.create_timer(Duration::from_secs(1)),
        true,
    ) else {
        return false;
    };

    // Set UART1 channel key.
    diffie_hellman_set_key(rt, &unpaired_ephemeral_public_key, &ephemeral_private_key);

    true
}
