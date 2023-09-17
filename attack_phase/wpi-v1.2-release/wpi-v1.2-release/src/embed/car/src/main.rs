#![no_std]
#![no_main]
#![warn(clippy::panic)]
#![warn(clippy::expect_used)]
#![warn(clippy::unwrap_used)]
#![deny(unused_results)]

use core::panic::PanicInfo;

mod features;
use chacha20poly1305::{XChaCha20Poly1305, KeyInit, AeadInPlace};
use features::FeatureMessage;

use ectf::{
    comms::io::IO,
    comms::message::{CarID, Password, UnlockMessage},
    comms::{packet::{Key, PacketIO}, message::EnableFeatureMessage, status::StatusIO},
    comms::{
        message::StartMessage,
        noncegenerator::{IncrementingNonceGenerator, NonceGenerator, NonceID},
    },
    double_down_if,
    hw::eeprom::*,
    hw::switches::*,
    hw::uart::{BridgeUart, HostUart},
    utils::{rng::{ImprovedCryptoRNG, RandomSource}, timing::{HardwareTimeKeeper, TimeKeeper}, static_slicing::StaticRangeIndex},
};

use ed25519_dalek::PublicKey as VerifyingKey;

use lazy_static::lazy_static;
use pbkdf2::pbkdf2_hmac_array;
use secrecy::Secret;

use sha2::Sha256;
use tm4c123x_hal as hal;
use tm4c123x_hal::prelude::*;
use tm4c123x_hal::sysctl;

use crate::error::{UnlockError, StartError};

mod error;

const PBKDF2_ROUNDS: u32 = 1000;

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

type CarResult<T> = Result<T, error::Error>;

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

    let key = EEPROMVar::<Key>::new::<SYM_KEY_EEPROM_ADDR>();
    let verifying_key = EEPROMVar::<[u8; 32]>::new::<VERIFYING_KEY_EEPROM_ADDR>();
    let nonce_id = EEPROMVar::<NonceID>::new::<NONCE_ID_EEPROM_ADDR>();

    let mut nonce_gen = IncrementingNonceGenerator::new(nonce_id);
    let mut rng = ImprovedCryptoRNG::new::<SEED_EEPROM_ADDR>();

    loop {
        let mut recv = [0u8; 2];
        BRIDGE_UART.read(&mut recv);

        if recv == *b"UC" {
            match unlock_car(&mut nonce_gen, &mut rng, &key, &verifying_key, &mut time_keeper) {
                Ok(_) => {},
                Err(e) => {
                    time_keeper.delay(3000);
                    HOST_UART.send_status(ectf::comms::status::Status::Error(e.get_status_code()));
                }
            }
        }
    }
}

fn unlock_car<K: for<'a> TimeKeeper<'a>>(
    nonce_gen: &mut IncrementingNonceGenerator,
    rng: &mut dyn RandomSource,
    key: &EEPROMVar<Key>,
    verifying_key: &EEPROMVar<[u8; 32]>,
    time_keeper: &mut K
) -> CarResult<()> {
    let unlock_message = EEPROMVar::<FeatureMessage>::new::<UNLOCK_MESSAGE_EEPROM_ADDR>();
    let correct_car_id = EEPROMVar::<CarID>::new::<CAR_ID_EEPROM_ADDR>();

    let nonce = nonce_gen.generate_nonce(rng)?;

    BRIDGE_UART.write(&nonce)?;

    let timeout = time_keeper.create_timeout(3000);
    let packet = BRIDGE_UART.read_packet_with_timeout(timeout)?;

    let verified_packet = packet.verify(nonce)?;
    let decrypted_packet = {
        let key_secret = Secret::new(key.read());
        verified_packet.decrypt(&key_secret)?
    };

    let UnlockMessage { passwd, id } = decrypted_packet.to_message()?;
    double_down_if!(
        id == correct_car_id.read(),
        {
            let pw_protected_payload = EEPROMVar::<[u8; 32]>::new::<PW_PROTECTED_PAYLOAD_ADDR>();
            let pw_protected_payload_nonce = EEPROMVar::<[u8; 24]>::new::<PW_PROTECTED_PAYLOAD_NONCE_ADDR>();
            let pw_derived_key_salt = EEPROMVar::<[u8; 16]>::new::<PW_DERIVED_KEY_SALT_ADDR>();
        
            let pw_derived_key = pbkdf2_hmac_array::<Sha256, 32>(passwd.as_bytes(), &pw_derived_key_salt.read(), PBKDF2_ROUNDS);

            let (mut pw_protected_payload, pw_protected_tag) = {
                let pw_protected_payload = pw_protected_payload.read();
                (pw_protected_payload[StaticRangeIndex::<0, 16>], pw_protected_payload[StaticRangeIndex::<16, 16>])
            };

            let pw_protected_payload_nonce = pw_protected_payload_nonce.read();
            let pw_protected_cipher = XChaCha20Poly1305::new(&pw_derived_key.into());
        
            pw_protected_cipher.decrypt_in_place_detached(
                &pw_protected_payload_nonce.into(),
                &id.u32().to_le_bytes(),
                &mut pw_protected_payload,
                &pw_protected_tag.into()
            ).map_err(|_| UnlockError::IncorrectPassword)?;

            // As a reminder, do not meddle in the affairs of wizards.
            double_down_if!(pw_protected_payload == *b"Correct Password", {
                double_down_if!(pw_protected_payload == *b"Correct Password", {
                    HOST_UART.write(&unlock_message.read())?;
                    BRIDGE_UART.send_status(ectf::comms::status::Status::Success);
                    
                    let timeout = time_keeper.create_timeout(3000);
                    BRIDGE_UART.check_success(timeout)?;
        
                    start_car(nonce_gen, rng, key, verifying_key, time_keeper)
                }, Err(UnlockError::IncorrectPassword.into()))
            }, Err(UnlockError::IncorrectPassword.into()))
        },
        Err(UnlockError::IncorrectCarID.into())
    )
}

fn start_car<K: for<'a> TimeKeeper<'a>>(
    nonce_gen: &mut IncrementingNonceGenerator,
    rng: &mut dyn RandomSource,
    key: &EEPROMVar<Key>,
    verifying_key: &EEPROMVar<[u8; 32]>,
    time_keeper: &mut K
) -> CarResult<()> {
    let feature_message_1 = EEPROMVar::<FeatureMessage>::new::<FEATURE_MSG_1_EEPROM_ADDR>();
    let feature_message_2 = EEPROMVar::<FeatureMessage>::new::<FEATURE_MSG_2_EEPROM_ADDR>();
    let feature_message_3 = EEPROMVar::<FeatureMessage>::new::<FEATURE_MSG_3_EEPROM_ADDR>();

    let correct_car_id = EEPROMVar::<CarID>::new::<CAR_ID_EEPROM_ADDR>();

    let nonce = nonce_gen.generate_nonce(rng)?;

    BRIDGE_UART.write(&nonce)?;

    let timeout = time_keeper.create_timeout(3000);
    let packet = BRIDGE_UART.read_packet_with_timeout(timeout)?;

    let verified_packet = packet.verify(nonce)?;
    let decrypted_packet = {
        let key_secret = Secret::new(key.read());
        verified_packet.decrypt(&key_secret)?
    };

    let StartMessage { id, num_features } = decrypted_packet.to_message()?;

    double_down_if!(id == correct_car_id.read(), {
        // "Start Features"
        BRIDGE_UART.send_status(ectf::comms::status::Status::Success);

        for _ in 0..num_features {
            let nonce = nonce_gen.generate_nonce(rng)?;
            BRIDGE_UART.write(&nonce)?;

            let timeout = time_keeper.create_timeout(3000);
            let feature_packet = BRIDGE_UART.read_packet_with_timeout(timeout)?;
            let feature_packet = feature_packet.verify(nonce)?;
            let feature_packet = {
                let key_secret = Secret::new(key.read());
                feature_packet.decrypt(&key_secret)?
            };

            let enable_feature_message = feature_packet.to_message::<EnableFeatureMessage>()?;
            let verifying_key = VerifyingKey::from_bytes(&verifying_key.read())?;
            let enable_feature_payload = enable_feature_message.verify_payload(&verifying_key)?;

            let val = enable_feature_payload.feature_id.val();

            double_down_if!(val == 1, HOST_UART.write(&feature_message_1.read())?);

            double_down_if!(val == 2, HOST_UART.write(&feature_message_2.read())?);

            double_down_if!(val == 3, HOST_UART.write(&feature_message_3.read())?);

            // "Next Feature"
            BRIDGE_UART.send_status(ectf::comms::status::Status::Success);
        }

        Ok(())
    }, Err(StartError::IncorrectCarID.into()))
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
