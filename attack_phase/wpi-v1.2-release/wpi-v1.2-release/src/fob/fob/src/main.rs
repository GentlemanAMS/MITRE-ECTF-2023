#![no_std]
#![no_main]
#![warn(clippy::panic)]
#![warn(clippy::expect_used)]
#![warn(clippy::unwrap_used)]
#![deny(unused_results)]

use core::panic::PanicInfo;
use ectf::{
    comms::io::IO,
    comms::message::{
        CarID, EnableFeatureMessage, FeatureNumber, Password, StartMessage, UnlockMessage,
    },
    comms::{
        message::{PairingFobInfoMessage, Pin, EnableFeaturePayload, VerifyingKeyMessage, PairingCryptoInfoMessage, PairRequestMessage},
        noncegenerator::{IncrementingNonceGenerator, NonceGenerator, NonceID},
        packet::{Key, Nonce, Packet, PacketIO, Prepared}, status::StatusIO,
    },
    double_down_if,
    hw::eeprom::*,
    hw::switches::*,
    hw::uart::{BridgeUart, HostUart},
    utils::{rng::{ImprovedCryptoRNG, RandomSource}, timing::{HardwareTimeKeeper, TimeKeeper}, static_slicing::{StaticRangeIndex, FixedSizeCopy}},
};
use error::{FeatureEnableError, PairingError};
use secrecy::{Secret, zeroize::Zeroizing};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use ed25519_dalek::PublicKey as VerifyingKey;

use lazy_static::lazy_static;

use tm4c123x_hal as hal;
use tm4c123x_hal::prelude::*;
use tm4c123x_hal::sysctl;

use chacha20poly1305::{XChaCha20Poly1305, AeadInPlace, KeyInit};
use pbkdf2::pbkdf2_hmac_array;

mod error;

type FobResult<T> = Result<T, error::Error>;

lazy_static! {
    static ref HOST_UART: &'static mut HostUart = {
        // PANIC JUSTIFICATION: 
        // A singleton constructor that's only called once will never fail.
        // If it does somehow fail, there's a bug in someone else's code, not ours.
        // (namely, the cortex_m library that provides the `singleton` macro.)
        #[allow(clippy::expect_used)]
        HostUart::new().expect("Host UART Failed to Init!")
    };
    
    static ref BRIDGE_UART: &'static mut BridgeUart = {
        // PANIC JUSTIFICATION: 
        // A singleton constructor that's only called once will never fail.
        // If it does somehow fail, there's a bug in someone else's code, not ours.
        // (namely, the cortex_m library that provides the `singleton` macro.)
        #[allow(clippy::expect_used)]
        BridgeUart::new().expect("Bridge UART Failed to Init!")
    };
}

const PBKDF2_ROUNDS: u32 = 1000;

// NOTE: If someone wants to move this go for it. Idk where else to put it
pub struct PairedStatus(u32);

impl PairedStatus {
    fn u32(&self) -> u32 {
        self.0
    }
}

impl From<PairedStatus> for u32 {
    fn from(value: PairedStatus) -> Self {
        value.u32()
    }
}

impl From<u32> for PairedStatus {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl PartialEq for PairedStatus {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

#[repr(align(4))]
#[derive(PartialEq)]
struct SavedFeatureInfo(FeatureNumber, EnableFeatureMessage);

#[no_mangle]
fn main() -> ! {
    // PANIC JUSTIFICATION: 
    // Neither of these two `take` calls can possibly produce `None` in this context,
    // therefore it is perfectly fine to crash if that somehow happens anyway. It's not
    // like we could actually recover from that, anyway.
    #[allow(clippy::expect_used)] let p = hal::Peripherals::take().expect("Peripheral initialization will never fail");
    #[allow(clippy::expect_used)] let cp = hal::CorePeripherals::take().expect("Peripheral initialization will never fail");

    let mut sc = p.SYSCTL.constrain();
    sc.clock_setup.oscillator = sysctl::Oscillator::Main(
        sysctl::CrystalFrequency::_16mhz,
        sysctl::SystemClock::UsePll(sysctl::PllOutputFrequency::_80_00mhz),
    );
    let _clocks = sc.clock_setup.freeze();

    let mut time_keeper = HardwareTimeKeeper::new(cp.SYST);

    setup_sw1();
    eeprom_init();

    HOST_UART.drain();
    BRIDGE_UART.drain();

    let mut key = EEPROMVar::<Key>::new::<SYM_KEY_EEPROM_ADDR>();
    let mut verifying_key = EEPROMVar::<[u8; 32]>::new::<VERIFYING_KEY_EEPROM_ADDR>();

    let nonce_id = EEPROMVar::<NonceID>::new::<NONCE_ID_EEPROM_ADDR>();

    let mut paired_status = EEPROMVar::<PairedStatus>::new::<PAIRED_STATUS_EEPROM_ADDR>();

    let mut nonce_gen = IncrementingNonceGenerator::new(nonce_id);
    let mut rng = ImprovedCryptoRNG::new::<SEED_EEPROM_ADDR>();

    loop {
        if HOST_UART.data_avail() {
            match HOST_UART.read_byte() {
                b'E' => match enable_feature(&key, &verifying_key, &mut time_keeper) {
                    Ok(_) => HOST_UART.send_status(ectf::comms::status::Status::Success),
                    Err(e) => HOST_UART.send_status(ectf::comms::status::Status::Error(e.get_status_code()))
                }
                b'P' => match pair_unpaired_fob(&mut nonce_gen, &mut rng, &mut time_keeper, &mut key, &mut verifying_key, &mut paired_status) {
                    Ok(_) => HOST_UART.send_status(ectf::comms::status::Status::Success),
                    Err(e) => HOST_UART.send_status(ectf::comms::status::Status::Error(e.get_status_code()))
                }
                _ => {}
            }
        }

        if BRIDGE_UART.data_avail() && BRIDGE_UART.read_byte() == b'P' {
            match pair_paired_fob(&mut nonce_gen, &mut rng, &mut time_keeper, &mut key, &mut verifying_key, &paired_status) {
                Ok(_) => HOST_UART.send_status(ectf::comms::status::Status::Success),
                Err(e) => {
                    time_keeper.delay(3000);
                    HOST_UART.send_status(ectf::comms::status::Status::Error(e.get_status_code()));
                }
            }
        }

        // When SW1 is pressed
        if read_sw1() {
            let paired: u32 = paired_status.read().u32();

            if paired == 1u32 && unlock_and_start_car(&mut rng, &key, &mut time_keeper).is_err() {
                time_keeper.delay(3000);
            }

            // Spin until SW1 is released
            loop {
                if !read_sw1() {
                    break;
                }
            }
        }
    }
}

fn unlock_and_start_car<K: for<'a> TimeKeeper<'a>>(rng: &mut dyn RandomSource, key: &EEPROMVar<Key>, time_keeper: &mut K) -> FobResult<()> {
    unlock_car(rng, key)?;

    let timeout = time_keeper.create_timeout(3000);
    BRIDGE_UART.check_success(timeout)?;

    start_car(rng, key, time_keeper)
}

fn pair_paired_fob<K: for<'a> TimeKeeper<'a>>(
    nonce_gen: &mut IncrementingNonceGenerator,
    rng: &mut dyn RandomSource,
    time_keeper: &mut K,
    key: &mut EEPROMVar<Key>,
    verifying_key: &mut EEPROMVar<[u8; 32]>,
    paired_status: &EEPROMVar<PairedStatus>
) -> FobResult<()> {
    let status = paired_status.read().u32();

    if status != 1 {
        return Err(PairingError::FobNotPaired.into());
    }

    // First, generate a public/private key pair.
    let our_private_key = {
        let mut secret_bytes: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
        rng.get_random_bytes(&mut secret_bytes[..]);

        StaticSecret::from(*secret_bytes)
    };
    let our_public_key = PublicKey::from(&our_private_key);
    BRIDGE_UART.write(our_public_key.as_bytes())?;

    // Receive the other side's public key.
    let timeout = time_keeper.create_timeout(3000);
    let mut their_public_key = [0u8; 32];
    BRIDGE_UART.read_with_timeout(&mut their_public_key, timeout)?;
    let their_public_key = PublicKey::from(their_public_key);

    // Signal that we're ready to continue.
    BRIDGE_UART.send_status(ectf::comms::status::Status::Success);

    // Wait for the other side to signal that they're ready to continue.
    let timeout = time_keeper.create_timeout(3000);
    BRIDGE_UART.check_success(timeout)?;

    // Generate a nonce that the other side will use for a pairing request packet
    let nonce = nonce_gen.generate_nonce(rng)?;
    BRIDGE_UART.write(&nonce)?;

    let timeout = time_keeper.create_timeout(3000);
    let packet = BRIDGE_UART.read_packet_with_timeout(timeout)?;
    let packet = packet.verify(nonce)?;
    let packet = packet.decrypt(&{
        Secret::new(Key::new(our_private_key.diffie_hellman(&their_public_key).to_bytes()))
    })?;

    let PairRequestMessage { pin } = packet.to_message()?;

    let car_id = EEPROMVar::<CarID>::new::<CAR_ID_EEPROM_ADDR>();
    let fob_id = EEPROMVar::<[u8; 32]>::new::<FOB_ID_ADDR>();
    let unlock_password = EEPROMVar::<Password>::new::<UNLOCK_PASSWD_EEPROM_ADDR>();

    let pin_protected_payload = EEPROMVar::<[u8; 32]>::new::<PIN_PROTECTED_PAYLOAD_ADDR>();
    let pin_protected_payload_nonce = EEPROMVar::<[u8; 24]>::new::<PIN_PROTECTED_PAYLOAD_NONCE_ADDR>();
    let pin_derived_key_salt = EEPROMVar::<[u8; 16]>::new::<PIN_DERIVED_KEY_SALT_ADDR>();

    // If paired:
    let pin_derived_key = {
        pbkdf2_hmac_array::<Sha256, 32>(pin.as_bytes(), &pin_derived_key_salt.read(), PBKDF2_ROUNDS)
    };

    let (mut pin_protected_payload, pin_protected_tag) = {
        let pin_protected_payload = pin_protected_payload.read();
        (pin_protected_payload[StaticRangeIndex::<0, 16>], pin_protected_payload[StaticRangeIndex::<16, 16>])
    };

    let pin_protected_payload_nonce = pin_protected_payload_nonce.read();

    let pin_protected_cipher = XChaCha20Poly1305::new(&pin_derived_key.into());
    let mut pin_protected_ad = [0u8; 36];

    pin_protected_ad[StaticRangeIndex::<0, 4>].copy_from(car_id.read().u32().to_le_bytes());
    pin_protected_ad[StaticRangeIndex::<4, 32>].copy_from(fob_id.read());

    pin_protected_cipher.decrypt_in_place_detached(
        &pin_protected_payload_nonce.into(),
        &pin_protected_ad,
        &mut pin_protected_payload,
        &pin_protected_tag.into()
    ).map_err(|_| PairingError::IncorrectPIN)?;

    // Do not meddle in the affairs of wizards, for they are subtle and quick to anger.
    // - J.R.R Tolkien, "The Fellowship of the Ring"
    double_down_if!(pin_protected_payload == *b"Correct Pair PIN", {
        double_down_if!(pin_protected_payload == *b"Correct Pair PIN", {
            // Signal that we're ready to continue.
            BRIDGE_UART.send_status(ectf::comms::status::Status::Success);

            // Receive nonce
            let timeout = time_keeper.create_timeout(3000);
            let mut nonce = [0u8; 24];
            BRIDGE_UART.read_with_timeout(&mut nonce, timeout)?;

            // Create packet containing car ID
            let nonce = Nonce::clone_from_slice(&nonce);

            let extension_nonce = {
                let mut extension_nonce = [0u8; 24];
                rng.get_random_bytes(&mut extension_nonce);
                extension_nonce
            };

            let new_fob_id = {
                let mut new_fob_id = [0u8; 32];
                rng.get_random_bytes(&mut new_fob_id);
                new_fob_id
            };

            let new_salt = {
                let mut new_salt = [0u8; 16];
                rng.get_random_bytes(&mut new_salt);
                new_salt
            };

            let msg = PairingFobInfoMessage {
                car_id: car_id.read(),
                fob_id: new_fob_id,
                extension_nonce,
                salt: new_salt
            };

            // Derive new key using the shared salt. Knowledge of the PIN is still required.
            let pin_derived_key = pbkdf2_hmac_array::<Sha256, 32>(pin.as_bytes(), &new_salt, PBKDF2_ROUNDS);

            // Encrypt with nonce
            let pkt = Packet::<Prepared>::new(rng, msg)?;
            {
                let shared_secret = our_private_key.diffie_hellman(&their_public_key);
                let shared_secret = Secret::new(Key::new(shared_secret.to_bytes()));
                let pkt = pkt.encrypt(&shared_secret, nonce)?;
                // Send to other fob
                BRIDGE_UART.write_packet(pkt)?;
            }

            // Receive nonce
            let timeout = time_keeper.create_timeout(3000);
            let mut nonce = [0u8; 24];
            BRIDGE_UART.read_with_timeout(&mut nonce, timeout)?;

            // Create packet containing car ID
            let nonce = Nonce::clone_from_slice(&nonce);

            let msg = PairingCryptoInfoMessage::new(
                ectf::comms::message::PairingCryptoInfoPayload { car_unlock_password: unlock_password.read(), car_symmetric_key: key.read() },
                Key::new(pin_derived_key),
                extension_nonce.into(),
                car_id.read(),
                new_fob_id
            )?;

            // Encrypt with nonce
            let pkt = Packet::<Prepared>::new(rng, msg)?;
            {
                let shared_secret = our_private_key.diffie_hellman(&their_public_key);
                let shared_secret = Secret::new(Key::new(shared_secret.to_bytes()));
                let pkt = pkt.encrypt(&shared_secret, nonce)?;
                // Send to other fob
                BRIDGE_UART.write_packet(pkt)?;
            }

            // Receive nonce
            let timeout = time_keeper.create_timeout(3000);
            let mut nonce = [0u8; 24];
            BRIDGE_UART.read_with_timeout(&mut nonce, timeout)?;

            // Create packet containing car's verifying key
            let nonce = Nonce::clone_from_slice(&nonce);

            let msg = VerifyingKeyMessage {
                verifying_key: verifying_key.read()
            };

            // Encrypt with nonce
            let pkt = Packet::<Prepared>::new(rng, msg)?;
            {
                let shared_secret = our_private_key.diffie_hellman(&their_public_key);
                let shared_secret = Secret::new(Key::new(shared_secret.to_bytes()));
                let pkt = pkt.encrypt(&shared_secret, nonce)?;
                // Send to other fob
                BRIDGE_UART.write_packet(pkt)?;
            }

            Ok(())
        }, Err(PairingError::IncorrectPIN.into()))
    }, Err(PairingError::IncorrectPIN.into()))
}

fn pair_unpaired_fob<K: for<'a> TimeKeeper<'a>>(
    nonce_gen: &mut IncrementingNonceGenerator,
    rng: &mut dyn RandomSource,
    time_keeper: &mut K,
    key: &mut EEPROMVar<Key>,
    verifying_key: &mut EEPROMVar<[u8; 32]>,
    paired_status: &mut EEPROMVar<PairedStatus>
) -> FobResult<()> {
    // Read PIN from host
    let mut pin_buf = [0u8; 6];
    HOST_UART.read(&mut pin_buf);

    let status = paired_status.read().u32();

    if status != 0 {
        return Err(PairingError::FobAlreadyPaired.into());
    }

    let pin = Pin::new(pin_buf).map_err(|_| PairingError::MalformedPIN)?;

    let mut car_id = EEPROMVar::<CarID>::new::<CAR_ID_EEPROM_ADDR>();
    let mut fob_id = EEPROMVar::<[u8; 32]>::new::<FOB_ID_ADDR>();
    let mut unlock_password = EEPROMVar::<Password>::new::<UNLOCK_PASSWD_EEPROM_ADDR>();

    let mut pin_protected_payload = EEPROMVar::<[u8; 32]>::new::<PIN_PROTECTED_PAYLOAD_ADDR>();
    let mut pin_protected_payload_nonce = EEPROMVar::<[u8; 24]>::new::<PIN_PROTECTED_PAYLOAD_NONCE_ADDR>();
    let mut pin_derived_key_salt = EEPROMVar::<[u8; 16]>::new::<PIN_DERIVED_KEY_SALT_ADDR>();

    // Send a pairing request to the other side
    BRIDGE_UART.write(b"xP")?;

    let timeout = time_keeper.create_timeout(3000);
    let mut their_public_key = [0u8; 32];
    BRIDGE_UART.read_with_timeout(&mut their_public_key, timeout)?;
    let their_public_key = PublicKey::from(their_public_key);

    let mut secret_bytes = [0u8; 32];
    rng.get_random_bytes(&mut secret_bytes);
    let our_private_key = StaticSecret::from(secret_bytes);
    let our_public_key = PublicKey::from(&our_private_key);

    BRIDGE_UART.write(our_public_key.as_bytes())?;

    // Make sure the other side is ready.
    let timeout = time_keeper.create_timeout(3000);
    BRIDGE_UART.check_success(timeout)?;

    // Signal that we're ready.
    BRIDGE_UART.send_status(ectf::comms::status::Status::Success);

    // Send a pair request.
    
    let timeout = time_keeper.create_timeout(3000);
    let mut nonce = [0u8; 24];
    BRIDGE_UART.read_with_timeout(&mut nonce, timeout)?;

    let nonce = Nonce::clone_from_slice(&nonce);
    
    let pkt = Packet::<Prepared>::new(rng, PairRequestMessage { pin })?;
    {
        let shared_secret = our_private_key.diffie_hellman(&their_public_key);
        let shared_secret = Secret::new(Key::new(shared_secret.to_bytes()));
        let pkt = pkt.encrypt(&shared_secret, nonce)?;
        // Send to other fob
        BRIDGE_UART.write_packet(pkt)?;
    }

    // Make sure the other side is ready.
    let timeout = time_keeper.create_timeout(3000);
    BRIDGE_UART.check_success(timeout)?;

    let nonce = nonce_gen.generate_nonce(rng)?;
    BRIDGE_UART.write(&nonce)?;

    // Receive packet, decrypt

    let timeout = time_keeper.create_timeout(3000);
    let packet = BRIDGE_UART.read_packet_with_timeout(timeout)?;

    let verified_packet = packet.verify(nonce)?;
    let decrypted_packet = {
        let shared_secret = our_private_key.diffie_hellman(&their_public_key);
        let shared_secret = Secret::new(Key::new(shared_secret.to_bytes()));

        verified_packet.decrypt(&shared_secret)?
    };

    let PairingFobInfoMessage {
        car_id: paired_car_id,
        fob_id: paired_fob_id,
        extension_nonce,
        salt
    } = decrypted_packet.to_message::<PairingFobInfoMessage>()?;

    // Derive a new key from the PIN and provided salt
    let pin_derived_key = pbkdf2_hmac_array::<Sha256, 32>(pin.as_bytes(), &salt, PBKDF2_ROUNDS);

    // Now we need to get the cryptographic material
    let nonce = nonce_gen.generate_nonce(rng)?;

    BRIDGE_UART.write(&nonce)?;

    let timeout = time_keeper.create_timeout(3000);
    let packet = BRIDGE_UART.read_packet_with_timeout(timeout)?;

    let verified_packet = packet.verify(nonce)?;
    let decrypted_packet = {
        let shared_secret = our_private_key.diffie_hellman(&their_public_key);
        let shared_secret = Secret::new(Key::new(shared_secret.to_bytes()));

        verified_packet
            .decrypt(&shared_secret)?
    };
    let crypto_material_msg = decrypted_packet.to_message::<PairingCryptoInfoMessage>()?;
    let crypto_material_payload = crypto_material_msg.into_payload(
        Key::new(pin_derived_key),
        extension_nonce.into(),
        paired_car_id,
        paired_fob_id
    )?;

    // Now we need to get the verifying key
    let nonce = nonce_gen.generate_nonce(rng)?;

    BRIDGE_UART.write(&nonce)?;

    let timeout = time_keeper.create_timeout(3000);
    let packet = BRIDGE_UART.read_packet_with_timeout(timeout)?;

    let verified_packet = packet.verify(nonce)?;
    let decrypted_packet = {
        let shared_secret = our_private_key.diffie_hellman(&their_public_key);
        let shared_secret = Secret::new(Key::new(shared_secret.to_bytes()));

        verified_packet.decrypt(&shared_secret)?
    };
    
    let verifying_key_msg = decrypted_packet.to_message::<VerifyingKeyMessage>()?;

    // Write basic info
    car_id.write(&paired_car_id);
    fob_id.write(&paired_fob_id);
    paired_status.write(&PairedStatus::from(1));

    // Write car's cryptographic material
    key.write(&crypto_material_payload.car_symmetric_key);
    unlock_password.write(&crypto_material_payload.car_unlock_password);
    verifying_key.write(&verifying_key_msg.verifying_key);

    // Write PIN-derived data

    let nonce = {
        let mut nonce = [0u8; 24];
        rng.get_random_bytes(&mut nonce);
        nonce
    };

    pin_derived_key_salt.write(&salt);
    pin_protected_payload_nonce.write(&nonce);
    pin_protected_payload.write(&{
        let cipher = XChaCha20Poly1305::new(&pin_derived_key.into());
        let mut full_payload = [0u8; 32];
        full_payload[StaticRangeIndex::<0, 16>].copy_from(*b"Correct Pair PIN");

        let mut associated_data = [0u8; 36];
        associated_data[StaticRangeIndex::<0, 4>].copy_from(paired_car_id.u32().to_le_bytes());
        associated_data[StaticRangeIndex::<4, 32>].copy_from(paired_fob_id);
        let tag = cipher.encrypt_in_place_detached(
            &nonce.into(), 
            &associated_data, 
            &mut full_payload[StaticRangeIndex::<0, 16>]
        )?;
        full_payload[StaticRangeIndex::<16, 16>].copy_from(tag.into());

        full_payload
    });

    Ok(())
}

fn enable_feature<K: for<'a> TimeKeeper<'a>>(key: &EEPROMVar<Key>, verifying_key: &EEPROMVar<[u8; 32]>, time_keeper: &mut K) -> FobResult<()> {

    // Read nonce from host
    let mut nonce = [0u8; 24];
    HOST_UART.read(&mut nonce);

    let nonce = Nonce::clone_from_slice(&nonce);

    // Read packet
    let timeout = time_keeper.create_timeout(5000);
    let pkt = HOST_UART.read_packet_with_timeout(timeout)?;

    // Decrypt packet
    let verified_packet = pkt.verify(nonce)?;

    let decrypted_packet = {
        let key_secret = Secret::new(key.read());
        verified_packet
        .decrypt(&key_secret)?
    };

    let correct_car_id = EEPROMVar::<CarID>::new::<CAR_ID_EEPROM_ADDR>();

    let msg = decrypted_packet.to_message::<EnableFeatureMessage>()?;

    let verifying_key = VerifyingKey::from_bytes(&verifying_key.read())?;
    let EnableFeaturePayload { 
        car_id, 
        feature_id 
    } = msg.verify_payload(&verifying_key)
            .map_err(|_| FeatureEnableError::InvalidSignature)?;

    // Verify car ID
    double_down_if!(
        car_id == correct_car_id.read(),
        {
            // Check if there's space left (fewer than 3 features have been enabled)

            let num_feat = EEPROMVar::<u32>::new::<NUM_FEATURES_EEPROM_ADDR>().read();

            if num_feat >= 3 {
                return Err(FeatureEnableError::NoSlotAvailable.into());
            }
            
            // Ensure this feature hasn't already been enabled
            let feat1 = match num_feat {
                0 => None,
                _ => Some(EEPROMVar::<SavedFeatureInfo>::new::<FEATURE_1_EEPROM_ADDR>().read()),
            };

            let feat2 = match num_feat {
                0 | 1 => None,
                _ => Some(EEPROMVar::<SavedFeatureInfo>::new::<FEATURE_2_EEPROM_ADDR>().read()),
            };

            let feat3 = match num_feat {
                0 | 1 | 2 => None,
                _ => Some(EEPROMVar::<SavedFeatureInfo>::new::<FEATURE_3_EEPROM_ADDR>().read()),
            };

            if matches!(feat1, Some(SavedFeatureInfo(fid, _)) if fid == feature_id)
            || matches!(feat2, Some(SavedFeatureInfo(fid, _)) if fid == feature_id)
            || matches!(feat3, Some(SavedFeatureInfo(fid, _)) if fid == feature_id) {
                return Err(FeatureEnableError::AlreadyEnabled.into());
            }

            // If all is good, add feature ID to list of enabled features

            let mut slot = match num_feat {
                0 => EEPROMVar::<SavedFeatureInfo>::new::<FEATURE_1_EEPROM_ADDR>(),
                1 => EEPROMVar::<SavedFeatureInfo>::new::<FEATURE_2_EEPROM_ADDR>(),
                2 => EEPROMVar::<SavedFeatureInfo>::new::<FEATURE_3_EEPROM_ADDR>(),
                _ => return Err(FeatureEnableError::NoSlotAvailable.into())
            };

            slot.write(&SavedFeatureInfo(feature_id, msg));

            EEPROMVar::<u32>::new::<NUM_FEATURES_EEPROM_ADDR>().write(&(num_feat + 1));

            Ok(())
        },
        Err(FeatureEnableError::InvalidCarID.into())
    )
}

fn unlock_car(rng: &mut dyn RandomSource, key: &EEPROMVar<Key>) -> FobResult<()> {
    // HOST_UART.write(b"FOB: Sw1 pressed! Sending unlock packet.\n");

    // Initiate unlock by sending U
    BRIDGE_UART.write(b"UC")?;

    // Get nonce from car
    let mut nonce = [0u8; 24];
    BRIDGE_UART.read(&mut nonce);
    let nonce = Nonce::clone_from_slice(&nonce);

    let unlock_password = EEPROMVar::<Password>::new::<UNLOCK_PASSWD_EEPROM_ADDR>();
    let car_id = EEPROMVar::<CarID>::new::<CAR_ID_EEPROM_ADDR>();

    let msg = UnlockMessage {
        id: car_id.read(),
        passwd: unlock_password.read(),
    };

    let pkt = Packet::<Prepared>::new(rng, msg)?;
    let pkt = {
        let key_secret = Secret::new(key.read());
        pkt.encrypt(&key_secret, nonce)?
    };

    BRIDGE_UART.write_packet(pkt)?;

    Ok(())
}

fn start_car<K: for<'a> TimeKeeper<'a>>(rng: &mut dyn RandomSource, key: &EEPROMVar<Key>, time_keeper: &mut K) -> FobResult<()> {
    BRIDGE_UART.send_status(ectf::comms::status::Status::Success);

    // Get nonce from car
    let mut nonce = [0u8; 24];
    BRIDGE_UART.read(&mut nonce);
    let nonce = Nonce::clone_from_slice(&nonce);

    let car_id = EEPROMVar::<CarID>::new::<CAR_ID_EEPROM_ADDR>();

    let num_feat = EEPROMVar::<u32>::new::<NUM_FEATURES_EEPROM_ADDR>().read();

    let msg = StartMessage {
        id: car_id.read(),
        num_features: num_feat,
    };

    let pkt = Packet::<Prepared>::new(rng, msg)?;
    let pkt = {
        let key_secret = Secret::new(key.read());
        pkt.encrypt(&key_secret, nonce)?
    };

    BRIDGE_UART.write_packet(pkt)?;

    // Deal with features
    let timeout = time_keeper.create_timeout(3000);
    BRIDGE_UART.check_success(timeout)?;

    let mut nonce = [0u8; 24];
    let feature_vars = [
        EEPROMVar::<SavedFeatureInfo>::new::<FEATURE_1_EEPROM_ADDR>(),
        EEPROMVar::<SavedFeatureInfo>::new::<FEATURE_2_EEPROM_ADDR>(),
        EEPROMVar::<SavedFeatureInfo>::new::<FEATURE_3_EEPROM_ADDR>(),
    ];

    for i in 0..num_feat {
        BRIDGE_UART.read(&mut nonce);
        let nonce = Nonce::clone_from_slice(&nonce);

        let packet = Packet::new(rng,feature_vars[i as usize].read().1)?;
        let packet = {
            let key_secret = Secret::new(key.read());
            packet.encrypt(&key_secret, nonce)?
        };

        BRIDGE_UART.write_packet(packet)?;
        let timeout = time_keeper.create_timeout(3000);
        BRIDGE_UART.check_success(timeout)?;
    }

    let timeout = time_keeper.create_timeout(3000);
    BRIDGE_UART.check_success(timeout)?;

    Ok(())
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
