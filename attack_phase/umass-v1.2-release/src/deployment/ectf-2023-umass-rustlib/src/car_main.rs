use crate::board_link::{MessagePacket, RecvPacketError, PwdOrPrecompute, server_side_auth};
use crate::packet_types::{UNLOCK_MAGIC, START_MAGIC, READY_MAGIC};
use crate::packet_types::{PacketCore, FeatureData};
use crate::mitre_hal::{
    UART_BOARD, UART_HOST, EEPROMRead, GPIOPinWrite,
    timer_rtc_wait_to_expiry, timer_rtc_is_running
};
use crate::constants::{GPIO_PORTF_BASE, GPIO_PIN_1, GPIO_PIN_2, GPIO_PIN_3};
use crate::rng_manager::{RNG, init_rng, ingest_entropy};

use crate::scramish::{ScramishServerHmacs, SHA256_OUT_LEN, SALT_LEN};
use crate::array_type::AlignedByteArr;
use bytemuck::cast_slice_mut;

const FEATURE_MSG_SIZE: u32 = 64;
const FEATURE_END: u32 = 0x7C0;

const UNLOCK_EEPROM_SIZE: u32 = 64;
const UNLOCK_EEPROM_LOC: u32 = 0x7C0;

extern "C" {
    static CAR_ID: u32;
}

/// Main function for the car example
/// Initializes the RF module and waits for a successful unlock attempt.
/// If successful prints out the unlock flag.
#[no_mangle]
pub extern "C" fn car_main() -> ! {
    init_rng();

    loop {
        unlock_car();
        ingest_entropy();
    }
}

const CAR_START_SERVER_KEY_LOC: u32 = 0x00;
const CAR_START_H_CLIENT_KEY_LOC: u32 = 0x20;
const CAR_START_SALT_LOC: u32 = 0x40;
/// Function that handles unlocking of car
fn unlock_car() {
    let car_id = unsafe { CAR_ID };
    // Read the relevant data from EEPROM
    let mut car_start_server_key = AlignedByteArr([0x00; SHA256_OUT_LEN]);
    let mut car_start_h_client_key = AlignedByteArr([0x00; SHA256_OUT_LEN]);
    let mut car_start_salt = AlignedByteArr([0x00; SALT_LEN]);
    unsafe {
        EEPROMRead(cast_slice_mut::<u8, u32>(&mut car_start_server_key).as_mut_ptr(), CAR_START_SERVER_KEY_LOC, SHA256_OUT_LEN.try_into().unwrap());
        EEPROMRead(cast_slice_mut::<u8, u32>(&mut car_start_h_client_key).as_mut_ptr(), CAR_START_H_CLIENT_KEY_LOC, SHA256_OUT_LEN.try_into().unwrap());
        EEPROMRead(cast_slice_mut::<u8, u32>(&mut car_start_salt).as_mut_ptr(), CAR_START_SALT_LOC, SALT_LEN.try_into().unwrap());
    }
    let pwd_data = ScramishServerHmacs::new(car_start_h_client_key.0, car_start_server_key.0);

    let rng_ref = unsafe {RNG.as_mut().unwrap()};
    // Do the SCRAMish authentication
    let precomputed_data = PwdOrPrecompute::Precompute { salt: car_start_salt.0, hmacs: pwd_data };
    if let Ok(key) = server_side_auth(
            rng_ref,
            Some(car_id),
            precomputed_data,
            UNLOCK_MAGIC) {
        let mut eeprom_message = [0u32; FEATURE_MSG_SIZE as usize/core::mem::size_of::<u32>()];
        unsafe {
            EEPROMRead(
                eeprom_message.as_mut_ptr(),
                UNLOCK_EEPROM_LOC,
                UNLOCK_EEPROM_SIZE,
            );
        }

        let eeprom_message_byte = bytemuck::bytes_of(&eeprom_message);
        UART_HOST.write_bytes(&eeprom_message_byte[..UNLOCK_EEPROM_SIZE as usize]);
        start_car(key);
    } else {
        unsafe {
            assert!(timer_rtc_is_running());
            // server_side_auth started the timer
            timer_rtc_wait_to_expiry(true);
        }
    }
}

/// Function that handles starting of car - feature list
fn start_car(key: [u8; SHA256_OUT_LEN]) {
    // Receive start message after signalling readiness
    UART_BOARD.write_byte(READY_MAGIC.into());

    let mut message = match MessagePacket::receive_board_message_by_type(START_MAGIC, &UART_BOARD) {
        Ok(msg) => msg,
        Err(RecvPacketError::NoPacket) => unreachable!("receive_board_message_by_type only errs on overflow"),
        Err(RecvPacketError::Overflow) => unsafe {
            assert!(timer_rtc_is_running());
            // server_side_auth from unlock_car started the timer
            timer_rtc_wait_to_expiry(true);
            return;
        }
    };
    if message.verify_hmac(&key).is_err() {
        return;
    }
    let mut feature_info = FeatureData::deserialize((message.buffer()).try_into().unwrap());

    // Verify correct car id
    let car_id = unsafe { CAR_ID };

    let all_features_good = feature_info.verify_signatures(car_id).is_ok();
    for feature in feature_info.features() {
        let feature_id = feature.feature();
        let mut eeprom_message = [0u32; FEATURE_MSG_SIZE as usize/core::mem::size_of::<u32>()];
        let offset = core::cmp::min(feature_id as u32 * FEATURE_MSG_SIZE, FEATURE_END);
        unsafe {
            EEPROMRead(
                eeprom_message.as_mut_ptr(),
                FEATURE_END - offset,
                FEATURE_MSG_SIZE,
            );
        }
        let eeprom_message_byte = bytemuck::bytes_of(&eeprom_message);
        UART_HOST.write_bytes(&eeprom_message_byte[..FEATURE_MSG_SIZE as usize]);
    }
    // Change LED color: green
    unsafe {
        GPIOPinWrite(GPIO_PORTF_BASE,
            GPIO_PIN_1 | GPIO_PIN_2 | GPIO_PIN_3,
            GPIO_PIN_3); // 123 rbg
    }
    if !all_features_good {
        unsafe {
            assert!(timer_rtc_is_running());
            // server_side_auth from unlock_car started the timer
            timer_rtc_wait_to_expiry(true);
        }
    }
}
