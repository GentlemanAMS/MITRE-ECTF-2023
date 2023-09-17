use crate::mitre_hal::{
    UART_BOARD, UART_HOST, GPIOPinRead, GPIOPinWrite,
    FlashProgram, FlashErase, EEPROMRead, EEPROMProgram,
    timer_rtc_start, timer_rtc_is_running, timer_rtc_wait_to_expiry
};
use crate::array_type::AlignedByteArr;
use crate::board_link::{MessagePacket, RecvPacketError, client_side_auth, server_side_auth, PwdOrPrecompute};
use crate::packet_types::{EnablePacket, FeatureData, PacketCore};
use crate::packet_types::{_PAIR_MAGIC, UNLOCK_MAGIC, START_MAGIC};
use crate::constants::*;
use crate::rng_manager::{RNG, init_rng, ingest_entropy};
use crate::FOB_STATE_PTR;
use crate::sleep;

use crate::scramish::{ScramishServerHmacs, HmacSha256, SHA256_OUT_LEN, SALT_LEN};
use bytemuck::{cast_slice, cast_slice_mut};

use hmac::Mac;

use zeroize::Zeroize;

use core::mem::size_of;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlashData {
    feature_info: FeatureData,
}

impl Default for FlashData {
    fn default() -> Self {
        Self {
            feature_info: Default::default()
        }
    }
}

const fn pad_x4(n: usize) -> usize {
    let ret = match n%4 {
        0 => n,
        _ => 4*((n/4)+1)
    };
    assert!(ret%4 == 0);
    ret
}

impl FlashData {
    /// Function that handles enabling a new feature on the fob.
    /// Err is bool as to whether this is a security failure or not
    fn enable_feature(&mut self) -> Result<(), bool> {
        if let Some(eeprom_car_id) = car_id() {
            // Read enable packet from UART
            let mut uart_buffer = [0u8; EnablePacket::SIZE];
            let read_length = UART_HOST.read(&mut uart_buffer);
            if read_length < EnablePacket::SIZE {
                // Error receiving signature packet
                return Err(false);
            }

            let enable_msg : EnablePacket = EnablePacket::deserialize(uart_buffer);

            // Check if the IDs are the same.
            if enable_msg.car_id() != eeprom_car_id {
                // Not the correct ID; do not enable feature.
                return Err(true);
            }

            // Check the signature on the feature
            if !enable_msg.verify_signature() {
                return Err(true);
            }

            let cur_features: &mut FeatureData = &mut self.feature_info;

            // Enable the feature.
            // Pass in None for car_id because we already did those checks
            let could_insert_feature = cur_features.insert_signed_feature(None, enable_msg.signed_feature());

            if could_insert_feature {
                self.save_fob_state();
                UART_HOST.write_bytes("Enabled".as_bytes());
                Ok(())
            } else {
                Err(false)
            }
        } else {
            Err(false)
        }
    }

    fn save_fob_state(&self) {
        let serialized_flash_data = AlignedByteArr(self.serialize());
        let c_serialized_flash_data = bytemuck::try_cast_slice::<u8, u32>(&serialized_flash_data).unwrap();
        unsafe {
            FlashErase(FOB_STATE_PTR);
            FlashProgram(c_serialized_flash_data.as_ptr(), FOB_STATE_PTR, (size_of::<u32>()*c_serialized_flash_data.len()) as u32);
        }
    }
}
impl PacketCore<{ pad_x4(FeatureData::SIZE) }> for FlashData {
    fn serialize(&self) -> [u8; Self::SIZE] {
        let mut serialized_flash_data = [0xff; Self::SIZE];

        serialized_flash_data[..FeatureData::SIZE].copy_from_slice(&self.feature_info.serialize());
        serialized_flash_data
    }
    fn deserialize(data: [u8; Self::SIZE]) -> Self {
        Self {
            feature_info: FeatureData::deserialize(data[..FeatureData::SIZE].try_into().unwrap())
        }
    }
}

const CAR_ID_LOC: u32 = 0x00;
const CAR_START_AUTH_LOC: u32 = 0x54;
fn unlock_car() -> Result<[u8; SHA256_OUT_LEN], ()> {
    // Read the relevant data from EEPROM
    let car_id = car_id().ok_or_else(|| ())?;
    let mut car_start_auth = AlignedByteArr([0x00; SHA256_OUT_LEN]);
    unsafe {
        EEPROMRead(cast_slice_mut::<u8, u32>(&mut car_start_auth).as_mut_ptr(), CAR_START_AUTH_LOC, SHA256_OUT_LEN.try_into().unwrap());
    }
    let rng_ref = unsafe {RNG.as_mut().unwrap()};
    client_side_auth(rng_ref, car_id, &car_start_auth, UNLOCK_MAGIC)
        .map(|(_, _, key)| key)
}
fn start_car(protocol_key: [u8; SHA256_OUT_LEN], feature_info: &FeatureData) {
    let mut msg = MessagePacket::new(
            START_MAGIC, 
            &feature_info.serialize(),
        );
    /*
     * Feature info size is 1+65*3=196
     * Packet with HMAC is 196+32=228 <= max size of 255
     * Adding an HMAC only fails if the packet size with HMAC would be too big
     */
    msg.add_hmac(&protocol_key).unwrap();
    // Wait for a ping to ensure car is ready to receive features
    let _sync_byte = UART_BOARD.read_byte();
    // assert_eq!(_sync_byte, READY_MAGIC);
    msg.send_board_message(&UART_BOARD);
}

fn car_id() -> Option<u32> {
    let mut car_id: u32 = 0xFFFFFFFF;
    unsafe {
        EEPROMRead(&mut car_id as *mut u32,
            CAR_ID_LOC, size_of::<u32>().try_into().unwrap());
    }
    match car_id {
        0xFFFFFFFF => None,
        id => Some(id)
    }
}

const FOB_PAIR_SERVER_KEY_LOC: u32 = 0x04;
const FOB_PAIR_H_CLIENT_KEY_LOC: u32 = 0x24;
const FOB_PAIR_SALT_LOC: u32 = 0x44;
fn pair_fob() {
    if let Some(car_id) = car_id() {
        // We are a paired fob

        let mut fob_pair_server_key = AlignedByteArr([0x00; SHA256_OUT_LEN]);
        let mut fob_pair_h_client_key = AlignedByteArr([0x00; SHA256_OUT_LEN]);
        let mut fob_pair_salt = AlignedByteArr([0x00; SALT_LEN]);
        unsafe {
            EEPROMRead(cast_slice_mut::<u8, u32>(&mut fob_pair_server_key).as_mut_ptr(), FOB_PAIR_SERVER_KEY_LOC, SHA256_OUT_LEN.try_into().unwrap());
            EEPROMRead(cast_slice_mut::<u8, u32>(&mut fob_pair_h_client_key).as_mut_ptr(), FOB_PAIR_H_CLIENT_KEY_LOC, SHA256_OUT_LEN.try_into().unwrap());
            EEPROMRead(cast_slice_mut::<u8, u32>(&mut fob_pair_salt).as_mut_ptr(), FOB_PAIR_SALT_LOC, SALT_LEN.try_into().unwrap());
        }
        let pwd_data = ScramishServerHmacs::new(fob_pair_h_client_key.0, fob_pair_server_key.0);

        let rng_ref = unsafe {RNG.as_mut().unwrap()};
        // Do the SCRAMish authentication
        let precomputed_data = PwdOrPrecompute::Precompute { salt: fob_pair_salt.0, hmacs: pwd_data };

        // Signal unpaired fob our car ID
        MessagePacket::new(_PAIR_MAGIC, &(car_id.to_le_bytes())).send_board_message(&UART_BOARD);

        if server_side_auth(
                rng_ref,
                Some(car_id),
                precomputed_data,
                _PAIR_MAGIC).is_ok() {
            UART_HOST.write_bytes(b"P");
        } else {
            unsafe {
                assert!(timer_rtc_is_running());
                // server_side_auth started the timer
                timer_rtc_wait_to_expiry(true);
            }
        }
    } else {
        // We are an unpaired fob

        let mut pin_verify = [0u8; 6];
        // PIN fits into UART FIFO entirely, so this would never overflow
        // Even then, we would have wrong pin -> expected "wrong pin" behavior
        UART_HOST.read(&mut pin_verify);

        let mut unpaired_auth_base = AlignedByteArr([0x00; SHA256_OUT_LEN]);
        unsafe {
            // unpaired_auth_base is stored in server key location
            EEPROMRead(cast_slice_mut::<u8, u32>(&mut unpaired_auth_base).as_mut_ptr(), FOB_PAIR_SERVER_KEY_LOC, SHA256_OUT_LEN.try_into().unwrap());
        }

        let car_id_msg = match MessagePacket::receive_board_message_by_type(_PAIR_MAGIC, &UART_BOARD) {
            Ok(msg) => msg,
            Err(RecvPacketError::NoPacket) => unreachable!("receive_board_message_by_type only errs on overflow"),
            Err(RecvPacketError::Overflow) => unsafe {
                timer_rtc_start(TIMER_PER_SEC*5);
                timer_rtc_wait_to_expiry(true);
                return;
            }
        };
        if car_id_msg.buffer().len() != size_of::<u32>() {
            return;
        }
        let car_id = u32::from_le_bytes(car_id_msg.buffer().try_into().unwrap());

        let mut hmac_pairing_auth = HmacSha256::new_from_slice(&unpaired_auth_base).unwrap();
        hmac_pairing_auth.update(car_id_msg.buffer());
        hmac_pairing_auth.update(&pin_verify);
        let pairing_auth: [u8; SHA256_OUT_LEN] = hmac_pairing_auth.finalize().into_bytes().into();
        unpaired_auth_base.zeroize();
        pin_verify.zeroize();

        let rng_ref = unsafe {RNG.as_mut().unwrap()};
        unsafe {timer_rtc_start(TIMER_PER_SEC*5);}
        if let Ok((server_hmacs, salt, _)) = client_side_auth(rng_ref, car_id,
                &pairing_auth, _PAIR_MAGIC) {
            let mut fob_pair_salt = AlignedByteArr([0x00; SALT_LEN]);
            let mut fob_pair_server_key = AlignedByteArr([0x00; SHA256_OUT_LEN]);
            let mut fob_pair_h_client_key = AlignedByteArr([0x00; SHA256_OUT_LEN]);
            fob_pair_salt.copy_from_slice(&salt);
            fob_pair_server_key.copy_from_slice(&server_hmacs.serverkey());
            fob_pair_h_client_key.copy_from_slice(&server_hmacs.h_clientkey());

            let mut car_start_base = AlignedByteArr([0x00; SHA256_OUT_LEN]);
            unsafe {
                EEPROMRead(cast_slice_mut::<u8, u32>(&mut car_start_base).as_mut_ptr(), CAR_START_AUTH_LOC, SHA256_OUT_LEN.try_into().unwrap());
            }
            let mut hmac_car_start_auth = HmacSha256::new_from_slice(&car_start_base).unwrap();
            hmac_car_start_auth.update(car_id_msg.buffer());
            let car_start_auth = hmac_car_start_auth.finalize().into_bytes();

            car_start_base.zeroize();
            let mut aligned_car_start_auth = AlignedByteArr([0x00; SHA256_OUT_LEN]);
            aligned_car_start_auth.copy_from_slice(&car_start_auth);

            unsafe {
                EEPROMProgram(&car_id as *const u32,
                    CAR_ID_LOC, size_of::<u32>().try_into().unwrap());
                EEPROMProgram(cast_slice::<u8, u32>(&aligned_car_start_auth).as_ptr(), CAR_START_AUTH_LOC, SHA256_OUT_LEN.try_into().unwrap());
                EEPROMProgram(cast_slice::<u8, u32>(&fob_pair_salt).as_ptr(), FOB_PAIR_SALT_LOC, SALT_LEN.try_into().unwrap());
                EEPROMProgram(cast_slice::<u8, u32>(&fob_pair_h_client_key).as_ptr(),
                    FOB_PAIR_H_CLIENT_KEY_LOC, SHA256_OUT_LEN.try_into().unwrap());
                EEPROMProgram(cast_slice::<u8, u32>(&fob_pair_server_key).as_ptr(),
                    FOB_PAIR_SERVER_KEY_LOC, SHA256_OUT_LEN.try_into().unwrap());

                // Change LED color: white
                GPIOPinWrite(GPIO_PORTF_BASE,
                    GPIO_PIN_1 | GPIO_PIN_2 | GPIO_PIN_3,
                    GPIO_PIN_1 | GPIO_PIN_2 | GPIO_PIN_3); // 123 rbg
            }
            UART_HOST.write_bytes(b"P");
        } else {
            unsafe {
                timer_rtc_wait_to_expiry(true);
            }
        }
    }
}

#[no_mangle]
pub extern "C" fn fob_main(should_be_paired: bool) -> ! {
    let fob_state_flash_slice = unsafe {
        core::slice::from_raw_parts(FOB_STATE_PTR as *const _, FlashData::SIZE)
    };
    let is_first_boot = fob_state_flash_slice.iter().all(|b| *b==0xFF);
    let fob_state_flash = FlashData::deserialize(fob_state_flash_slice.try_into().unwrap());
    let mut fob_state_ram = FlashData::default();

    // If we are supposed to be paired, assert that we have a Car ID stored
    // Car ID should have been placed in EEPROM by build process
    if should_be_paired {
        assert!(car_id().is_some(), "Car ID is unpaired value but should be paired");
    }
    // Run on first boot to initialize feature count
    if is_first_boot {
        fob_state_ram.save_fob_state();
    } else {
        fob_state_ram = fob_state_flash;
    }
    let mut is_paired = car_id().is_some();
    if is_paired {
        unsafe {
            // Change LED color: white
            GPIOPinWrite(GPIO_PORTF_BASE,
                GPIO_PIN_1 | GPIO_PIN_2 | GPIO_PIN_3,
                GPIO_PIN_1 | GPIO_PIN_2 | GPIO_PIN_3); // 123 rbg
        }
    } else {
        unsafe {
            // cyan
            GPIOPinWrite(GPIO_PORTF_BASE,
                GPIO_PIN_1 | GPIO_PIN_2 | GPIO_PIN_3,
                GPIO_PIN_2 | GPIO_PIN_3
            ); // 123 rbg
        }
    }
    // We do not need the fob_state_flash struct ever again
    // So we don't have to update it

    init_rng();

    let mut previous_sw_state: u8 = GPIO_PIN_4 as u8;
    let mut debounce_sw_state: u8;
    let mut current_sw_state:  u8;

    loop {
        if UART_HOST.available() {
            // Host should send only a single character command
            // If host is spewing garbage and causing FIFO overflow we don't want to listen anyways
            let uart_char = UART_HOST.read_byte();
            if uart_char == Ok(b'e') {
                unsafe {timer_rtc_start(TIMER_PER_SEC*5);}
                let enable_result = fob_state_ram.enable_feature();
                ingest_entropy();
                if enable_result == Err(true) {
                    unsafe {timer_rtc_wait_to_expiry(true);}
                }
            } else if uart_char == Ok(b'p') {
                // pair_fob includes timer handling
                pair_fob();
                is_paired = car_id().is_some();
                ingest_entropy();
            }
        }
        current_sw_state = unsafe { GPIOPinRead(GPIO_PORTF_BASE, GPIO_PIN_4) as u8 };
        if is_paired && (current_sw_state != previous_sw_state) && (current_sw_state == 0) {
            // Debounce switch
            sleep(10000);
            debounce_sw_state = unsafe { GPIOPinRead(GPIO_PORTF_BASE, GPIO_PIN_4) as u8 };
            if debounce_sw_state == current_sw_state {
                unsafe {timer_rtc_start(TIMER_PER_SEC*5);}
                if let Ok(protocol_key) = unlock_car() {
                    // start_car is a message transmission without a status
                    start_car(protocol_key, &fob_state_ram.feature_info);
                    ingest_entropy();
                } else {
                    unsafe {timer_rtc_wait_to_expiry(true);}
                }
            }
        }
        previous_sw_state = current_sw_state;
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{NUM_FEATURES, packet_types::{SignedFeature, SIGNATURE_SIZE}};

    extern crate std;
    #[test]
    fn verify_flash_data_roundtrip() {
        let mut feature_data = FeatureData::default();
        for i in 0..NUM_FEATURES {
            feature_data.insert_signed_feature(None, SignedFeature::new([0x10; SIGNATURE_SIZE], i as u8));
        }

        let orig_packet = FlashData{feature_info: feature_data};
        let serialized = orig_packet.serialize();

        let ret_packet = FlashData::deserialize(serialized);
        assert_eq!(orig_packet, ret_packet);

        // FlashData has end padding so don't do no-end-padding check
        /*let mut serialized_copy = serialized.clone();
        serialized_copy[FlashData::SIZE-1] = 0xFF;
        let mod_packet = FlashData::deserialize(serialized_copy);
        assert_ne!(orig_packet, mod_packet);*/
    }
}
