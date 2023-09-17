use crate::mitre_hal::{UART, UART_BOARD, timer_rtc_start};
use crate::packet_types::{SCRAMISH_SUCCESS_MAGIC, SCRAMISH_FAIL_MAGIC};
use crate::scramish::{ScramishClient, ScramishServer, ScramishServerHmacs, SALT_LEN, client_key, server_key};
use crate::scramish::{CLIENT_FIRST_LEN, SERVER_FIRST_LEN, CLIENT_FINISH_LEN, SERVER_FINISH_LEN, SHA256_OUT_LEN};
use crate::constants::TIMER_PER_SEC;

use core::num::NonZeroU8;

use heapless::Vec;
use rand_core::RngCore;

use sha2::{Sha256, Digest};
use crate::scramish::HmacSha256;
use hmac::Mac;
use hmac::digest::MacError;

const MAX_PACKET_LEN: usize = u8::MAX as usize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessagePacketHmacError {
    BufferTooShort,
    BufferTooLong,
    HmacWrong(MacError)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessagePacket {
    magic: NonZeroU8,
    buffer: Vec<u8, MAX_PACKET_LEN>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum RecvPacketError {
    NoPacket,
    Overflow
}

impl MessagePacket {
    pub fn new(magic: NonZeroU8, buffer: &[u8]) -> Self {
        // Use assert to catch buffer that is too big
        // Callers should confirm that passed buffers aren't too large
        assert!(buffer.len() < u8::MAX.into());
        Self {
            magic,
            buffer: Vec::from_slice(buffer).unwrap(),
        }
    }
    #[inline(always)]
    pub fn magic(&self) -> NonZeroU8 {
        self.magic
    }
    #[inline(always)]
    pub fn buffer(&self) -> &[u8] {
        self.buffer.as_ref()
    }

    /// Appends an HMAC tag to the buffer.
    pub fn add_hmac(&mut self, key: &[u8]) -> Result<(), MessagePacketHmacError> {
        if self.buffer.len() + SHA256_OUT_LEN > MAX_PACKET_LEN {
            return Err(MessagePacketHmacError::BufferTooLong);
        }
        let mut hmac_inst = HmacSha256::new_from_slice(key).unwrap();
        hmac_inst.update(&[self.magic.into()]);
        hmac_inst.update(&[self.buffer.len().try_into().unwrap()]);
        hmac_inst.update(&self.buffer);
        self.buffer.extend(hmac_inst.finalize().into_bytes());
        Ok(())
    }
    /// Verifies the HMAC and chops off the tag from the buffer if good.
    pub fn verify_hmac(&mut self, key: &[u8]) -> Result<(), MessagePacketHmacError> {
        if self.buffer.len() < SHA256_OUT_LEN {
            return Err(MessagePacketHmacError::BufferTooShort);
        }
        let (msg, tag) = self.buffer.split_at(self.buffer.len()-SHA256_OUT_LEN);
        // Check that we split the buffer correctly (should be optimized out)
        assert_eq!(tag.len(), SHA256_OUT_LEN);
        let mut hmac_inst = HmacSha256::new_from_slice(key).unwrap();
        hmac_inst.update(&[self.magic.into()]);
        hmac_inst.update(&[msg.len().try_into().unwrap()]);
        hmac_inst.update(msg);
        match hmac_inst.verify(tag.into()) {
            Ok(()) => {
                // Would only fail if expanding too big, but we're shrinking
                self.buffer.resize_default(self.buffer.len()-SHA256_OUT_LEN).unwrap();
                Ok(())
            },
            Err(e) => Err(MessagePacketHmacError::HmacWrong(e))
        }
    }

    pub fn send_board_message(self, uart: &UART) {
        uart.write_byte(self.magic.into());
        uart.write_byte(self.buffer.len().try_into().unwrap());
        uart.write_bytes(&self.buffer);
    }

    fn receive_board_message(uart: &UART) -> Result<Self, RecvPacketError> {
        let magic = NonZeroU8::new(
            uart.read_byte().map_err(|_| RecvPacketError::Overflow)?)
            .ok_or(RecvPacketError::NoPacket)?;

        let message_len = uart.read_byte().map_err(|_| RecvPacketError::Overflow)?;
        
        let mut buffer = Vec::new();
        for _ in 0..message_len {
            // u8 max = Vec capacity so this can never fail
            buffer.push(uart.read_byte().map_err(|_| RecvPacketError::Overflow)?).unwrap();
        }

        Ok(MessagePacket { magic, buffer })
    }

    pub fn receive_board_message_by_type(type_t: NonZeroU8, uart: &UART) -> Result<MessagePacket, RecvPacketError> {
        loop {
            let recv = MessagePacket::receive_board_message(uart);
            match recv {
                Ok(packet) => {
                    if packet.magic == type_t {
                        break Ok(packet);
                    }
                },
                Err(RecvPacketError::NoPacket) => {/* Do nothing */},
                Err(RecvPacketError::Overflow) => {break Err(RecvPacketError::Overflow);}
            }
        }
    }

    fn receive_board_message_nonzero_magic(uart: &UART) -> Result<MessagePacket, RecvPacketError> {
        loop {
            match MessagePacket::receive_board_message(uart) {
                Ok(msg) => {break Ok(msg);},
                Err(RecvPacketError::NoPacket) => {/* Do nothing */},
                Err(RecvPacketError::Overflow) => {break Err(RecvPacketError::Overflow);}
            }
        }
    }
}

// Return the HMACs, salt, and protocol key, not just the protocol key
// Returning the first two allows the client to become a server
pub fn client_side_auth<R: RngCore+?Sized>(rng: &mut R, car_id: u32, pwd: &[u8], magic: NonZeroU8) -> Result<(ScramishServerHmacs, [u8; SALT_LEN], [u8; SHA256_OUT_LEN]), ()> {
    match client_side_auth_inner(rng, car_id, pwd, magic) {
        Ok(tup) => Ok(tup),
        Err(e) => {
            MessagePacket::new(SCRAMISH_FAIL_MAGIC, &[]).send_board_message(&UART_BOARD);
            Err(e)
        }
    }
}
fn client_side_auth_inner<R: RngCore+?Sized>(rng: &mut R, car_id: u32, pwd: &[u8], magic: NonZeroU8) -> Result<(ScramishServerHmacs, [u8; SALT_LEN], [u8; SHA256_OUT_LEN]), ()> {
    let mut client = ScramishClient::with_rng(rng);

    let client_first = client.client_first(car_id);
    MessagePacket::new(magic, &client_first).send_board_message(&UART_BOARD);

    let server_first = MessagePacket::receive_board_message_nonzero_magic(&UART_BOARD)
        .map_err(|_| ())?;
    let server_first_buf = if server_first.magic() == magic {
        server_first.buffer()
    } else {
        // SCRAMish protocol doesn't abort at this step
        return Err(());
    };
    if server_first_buf.len() != SERVER_FIRST_LEN {
        return Err(());
    }

    let client_final = client.handle_server_first(pwd, server_first_buf.try_into().unwrap(), None).map_err(|_| ())?;
    let salt = client.salt();
    let salted_pwd = client.salted_password();

    MessagePacket::new(magic, &client_final).send_board_message(&UART_BOARD);

    let server_final = MessagePacket::receive_board_message_nonzero_magic(&UART_BOARD)
        .map_err(|_| ())?;
    let server_final_buf = if server_final.magic() == magic {
        server_final.buffer()
    } else if server_final.magic() == SCRAMISH_FAIL_MAGIC {
        // We might set a flag for debugging here
        return Err(());
    } else {
        return Err(());
    };
    if server_final_buf.len() != SERVER_FINISH_LEN {
        return Err(());
    }

    let client_protocol_key = client.handle_server_final(server_final_buf.try_into().unwrap()).map_err(|_| ())?;

    // Confirm success (not in base SCRAM protocol)
    // Empty packet has enough space to have attached HMAC
    let mut success_packet = MessagePacket::new(SCRAMISH_SUCCESS_MAGIC, &[]);
    success_packet.add_hmac(&client_protocol_key).unwrap();
    success_packet.send_board_message(&UART_BOARD);

    let server_hmacs = ScramishServerHmacs::new(Sha256::digest(client_key(salted_pwd)).into(), server_key(salted_pwd));

    Ok((server_hmacs, salt, client_protocol_key))
}

// Struct allows either direct pwd storage or precomputed value storage
#[derive(Debug)]
pub enum PwdOrPrecompute<'a> {
    Pwd(&'a [u8]),
    Precompute{salt: [u8; SALT_LEN], hmacs: ScramishServerHmacs}
}

pub fn server_side_auth<R: RngCore+?Sized>(rng: &mut R, car_id: Option<u32>, pwd_storage: PwdOrPrecompute, magic: NonZeroU8) -> Result<[u8; SHA256_OUT_LEN], ()> {
    match server_side_auth_inner(rng, car_id, pwd_storage, magic) {
        Ok(key) => {
            Ok(key)
        },
        Err(e) => {
            if e {
                MessagePacket::new(SCRAMISH_FAIL_MAGIC, &[]).send_board_message(&UART_BOARD);
            }
            Err(())
        }
    }
}
fn server_side_auth_inner<R: RngCore+?Sized>(rng: &mut R, car_id: Option<u32>, pwd_storage: PwdOrPrecompute, magic: NonZeroU8) -> Result<[u8; SHA256_OUT_LEN], bool> {
    let (pwd, mut server) = match pwd_storage {
        PwdOrPrecompute::Pwd(pwd) => (Some(pwd), ScramishServer::with_rng(rng)),
        PwdOrPrecompute::Precompute { salt, hmacs } => (None, ScramishServer::with_rng_and_pwd_storage(rng, salt, hmacs))
    };

    let client_first = MessagePacket::receive_board_message_nonzero_magic(&UART_BOARD)
        .map_err(|_| true)?;
    unsafe {timer_rtc_start(TIMER_PER_SEC*5);}
    let client_first_buf = if client_first.magic() == magic {
        client_first.buffer()
    } else {
        // SCRAMish protocol doesn't abort at this step
        return Err(true);
    };
    if client_first_buf.len() != CLIENT_FIRST_LEN {
        return Err(true);
    }

    let (recv_uid, server_first) = server.handle_client_first(client_first_buf.try_into().unwrap());
    if let Some(car_id) = car_id {
        if car_id != recv_uid {
            return Err(true);
        }
    }
    MessagePacket::new(magic, &server_first).send_board_message(&UART_BOARD);

    if let Some(p) = pwd {
        server.emplace_salted_pwd(p.as_ref(), None);
    }

    let client_final = MessagePacket::receive_board_message_nonzero_magic(&UART_BOARD)
        .map_err(|_| true)?;
    let client_final_buf = if client_first.magic() == magic {
        client_final.buffer()
    } else if client_final.magic() == SCRAMISH_FAIL_MAGIC {
        // We might set a flag for debugging here
        return Err(true);
    } else {
        return Err(true);
    };
    if client_final_buf.len() != CLIENT_FINISH_LEN {
        return Err(true);
    }

    let (server_final, server_protocol_key) = match server.handle_client_final(client_final_buf.try_into().unwrap()) {
        Ok(tup) => tup,
        Err(_e) => {return Err(true);}
    };
    MessagePacket::new(magic, &server_final).send_board_message(&UART_BOARD);

    let mut client_sig = MessagePacket::receive_board_message_nonzero_magic(&UART_BOARD)
        .map_err(|_| false)?;
    match client_sig.magic {
        SCRAMISH_SUCCESS_MAGIC => { /* Do nothing */},
        SCRAMISH_FAIL_MAGIC => {return Err(false);}, // We might set a flag for debugging here
        _ => {return Err(false);}
    }

    if client_sig.verify_hmac(&server_protocol_key).is_ok() {
        Ok(server_protocol_key)
    } else {
        Err(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    extern crate std;
    #[test]
    fn verify_roundtrip() {
        let key = b"strawberry double jump";
        let mut success_packet = MessagePacket::new(SCRAMISH_SUCCESS_MAGIC, b"madeline");
        success_packet.add_hmac(key).unwrap();
        success_packet.verify_hmac(key).unwrap();
    }
    #[test]
    fn nonverify_roundtrip() {
        let key = b"strawberry double jump";
        let mut success_packet = MessagePacket::new(SCRAMISH_FAIL_MAGIC, b"badeline");
        success_packet.add_hmac(key).unwrap();
        success_packet.magic = SCRAMISH_SUCCESS_MAGIC;
        success_packet.verify_hmac(key).unwrap_err();
    }
}
