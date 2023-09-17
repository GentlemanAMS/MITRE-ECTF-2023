//! Packet generation and processing functionality.
use core::marker::PhantomData;
use core::ops::Deref;

use crate::{comms::io::IO, double_down_if, utils::{rng::RandomSource, static_slicing::{StaticRangeIndex, FixedSizeCopy}, timing::Timeout}};
use chacha20poly1305::{AeadInPlace, KeyInit, Tag, XChaCha20Poly1305};

pub use chacha20poly1305::XNonce as Nonce;
use secrecy::{zeroize::DefaultIsZeroes, ExposeSecret, Secret};

use super::error::Error;
use super::message::Message;

/// A key compatible with the XChaCha20Poly1305 algorithm.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Key(chacha20poly1305::Key);

impl Key {
    /// Constructs a [`Key`] from an array of 32 bytes.
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(chacha20poly1305::Key::from(bytes))
    }
}

impl From<Key> for [u8; 32] {
    fn from(value: Key) -> Self {
        value.0.into()
    }
}

impl DefaultIsZeroes for Key {}
impl Deref for Key {
    type Target = chacha20poly1305::Key;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Type-state for a [`Packet`] that has not yet been subject to nonce verification.
pub struct UnVerified;

/// Type-state for a [`Packet`] that is encrypted and ready to be sent.
pub struct Encrypted;

/// Type-state for a [`Packet`] that has been decrypted and can be inspected.
pub struct Decrypted;

/// Type-state for a [`Packet`] that has been constructed and is ready to be encrypted.
pub struct Prepared;

/// A packet of data with an associated nonce and authentication tag.
pub struct Packet<State> {
    body: [u8; 88],
    nonce: Nonce,
    hmac: Tag,
    state: PhantomData<State>,
}

impl Packet<UnVerified> {
    ///constructs a new unverified packet
    fn new(body: [u8; 88], nonce: Nonce, hmac: Tag) -> Self {
        Self {
            body,
            nonce,
            hmac,
            state: PhantomData,
        }
    }

    /// verifies the nonce. If the nonce is valid, produces an identical [`Packet<Encrypt>`].
    /// If nonce is not valid, produces a PAREDError 
    pub fn verify(self, nonce: Nonce) -> Result<Packet<Encrypted>, Error> {
        double_down_if!(
            nonce == self.nonce,
            Ok(Packet::<Encrypted> {
                body: self.body,
                nonce: self.nonce,
                hmac: self.hmac,
                state: PhantomData,
            }),
            Err(Error::InvalidNonce)
        )
    }
}

impl Packet<Encrypted> {
    /// Attempts to decrypt an encrypted packet. If attempt is unsuccessful, produces a PAREDError
    pub fn decrypt(mut self, key: &Secret<Key>) -> Result<Packet<Decrypted>, Error> {
        let cipher = XChaCha20Poly1305::new(key.expose_secret());
        cipher
            .decrypt_in_place_detached(&self.nonce, b"", &mut self.body, &self.hmac)?;

        Ok(Packet {
            body: self.body,
            nonce: self.nonce,
            hmac: self.hmac,
            state: PhantomData,
        })
    }
}

impl Packet<Decrypted> {
    /// Attempts to extract a message from a decrypted packet.
    /// If attempt is unsuccessful, produces a PAREDError
    #[allow(clippy::unwrap_used)]
    pub fn to_message<M>(self) -> Result<M, Error>
    where
        M: Message,
    {
        let (id_part, msg_part) = self.body.split_at(4);
        let id = u32::from_le_bytes(id_part.try_into().unwrap());

        if id == M::TYPE_ID {
            M::deserialize_from(msg_part.try_into().unwrap())
        } else {
            Err(Error::InvalidMessageIDError)
        }
    }
}

impl Packet<Prepared> {
    /// attempts to put a message into an unencrypted packet
    /// if attempt is not successful, will produce a PAREDError
    #[allow(clippy::unwrap_used)]
    pub fn new<M>(rng: &mut dyn RandomSource, message: M) -> Result<Self, Error>
    where
        M: Message,
    {
        let body = {
            let mut body: [u8; 88] = [0; 88];

            let (id_part, msg_part) = body.split_at_mut(4);

            id_part.copy_from_slice(&M::TYPE_ID.to_le_bytes()[..]);
            rng.get_random_bytes(msg_part);
            message.serialize_to(msg_part.try_into().unwrap())?;

            body
        };

        Ok(Self {
            body,
            nonce: Nonce::default(),
            hmac: Tag::default(),
            state: PhantomData,
        })
    }

    /// attempts to encrypt a prepared packet. If unsuccessful, produces a PAREDError.
    pub fn encrypt(
        mut self,
        key: &Secret<Key>,
        nonce: Nonce,
    ) -> Result<Packet<Encrypted>, Error> {
        let cipher = XChaCha20Poly1305::new(key.expose_secret());

        let hmac = cipher
            .encrypt_in_place_detached(&nonce, b"", &mut self.body)?;
        Ok(Packet {
            body: self.body,
            nonce,
            hmac,
            state: PhantomData,
        })
    }
}

fn parse_packet(data: [u8; 128]) -> Packet<UnVerified> {
    Packet::<UnVerified>::new(
        data[StaticRangeIndex::<0, 88>], 
        data[StaticRangeIndex::<88, 24>].into(), 
        data[StaticRangeIndex::<112, 16>].into())
}

/// A channel that can send and receive [`Packet`]s.
pub trait PacketIO: IO {
    // Writes a packet to the channel.
    fn write_packet(&self, p: Packet<Encrypted>) -> Result<(), Error> {
        let mut entire_packet = [0u8; 128];
        entire_packet[StaticRangeIndex::<0, 88>].copy_from(p.body);
        entire_packet[StaticRangeIndex::<88, 24>].copy_from(p.nonce.into());
        entire_packet[StaticRangeIndex::<112, 16>].copy_from(p.hmac.into());

        Ok(self.write(&entire_packet)?)
    }

    unsafe fn read_packet(&self) -> Packet<UnVerified> {
        let mut entire_packet = [0u8; 128];
        self.read(&mut entire_packet);
        parse_packet(entire_packet)
    }

    /// Attempts to read a packet from the channel, returning an error 
    /// if the provided timeout is exceeded.
    fn read_packet_with_timeout<'a, T: Timeout>(&'a self, timeout: T) -> Result<Packet<UnVerified>, Error> {
        let mut entire_packet = [0u8; 128];
        self.read_with_timeout(&mut entire_packet, timeout)?;
        Ok(parse_packet(entire_packet))
    }
}

// Tests

#[cfg(test)]
mod test {
    use core::cell::RefCell;

    use super::*;
    use crate::{
        comms::message::*,
        comms::noncegenerator::{IncrementingNonceGenerator, NonceGenerator, NonceID},
        hw::eeprom::{eeprom_scope, EEPROMVar},
        test::DummyIO,
        utils::rng::CryptoRNG,
    };
    use dudect_bencher::{
        rand::{Fill, Rng},
        BenchRng, Class,
    };
    use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
    use std::sync::Mutex;

    #[test]
    fn invalid_pin() {
        let _ = Pin::new(*b"INVALI").expect_err("Successfully parsed invalid PIN");
    }

    #[test]
    fn packet_encrypt_decrypt() -> Result<(), Error> {
        eeprom_scope(|| {
            let key = EEPROMVar::<Key>::new::<0x100>();
            let key_secret = Secret::new(key.read());

            let nonce = EEPROMVar::<NonceID>::new::<0x0>();
            let mut dummy_nonce = IncrementingNonceGenerator::new(nonce);

            let mut rng = CryptoRNG::new([0; 32]);

            let msg = PairRequestMessage {
                pin: Pin::new(*b"DEADBE")?,
            };

            let nonce = dummy_nonce.generate_nonce(&mut rng)?;

            let mut packet = Packet::<Prepared>::new(&mut rng, msg)?;

            let mut packet = packet.encrypt(&key_secret, nonce)?;

            let cipher = XChaCha20Poly1305::new(key_secret.expose_secret());

            dbg!(packet.nonce);
            dbg!(packet.body);
            dbg!(packet.hmac);

            // Make sure our plaintext didn't make it through unencrypted
            assert_ne!(packet.body[0..4], [1, 0, 0, 0]);
            assert_ne!(packet.body[4..10], *b"DEADBE");

            cipher
                .decrypt_in_place_detached(
                    &packet.nonce.into(),
                    b"",
                    &mut packet.body,
                    &packet.hmac.into(),
                )?;

            // Make sure we unencrypted the correct values
            assert_eq!(packet.body[0..4], [1, 0, 0, 0]);
            assert_eq!(packet.body[4..10], *b"DEADBE");
            Ok(())
        })
    }

    #[test]
    fn pairreq_ser_deser() -> Result<(), Error> {
        eeprom_scope(|| {
            let nonce = EEPROMVar::<NonceID>::new::<0x0>();
            let key = EEPROMVar::<Key>::new::<0x100>();
            let mut dummy_nonce = IncrementingNonceGenerator::new(nonce);
            let mut rng = CryptoRNG::new([0; 32]);

            let msg = PairRequestMessage {
                pin: Pin::new(*b"DEADBE").unwrap(),
            };

            let msg_c = msg.clone();

            let nonce = dummy_nonce.generate_nonce(&mut rng).unwrap();

            let key_secret = Secret::new(key.read());
            let packet = Packet::<Prepared>::new(&mut rng, msg).unwrap();
            let packet = packet.encrypt(&key_secret, nonce).unwrap();

            let packet = packet.decrypt(&key_secret).unwrap();

            let msg_2 = packet.to_message().unwrap();

            assert_eq!(msg_c, msg_2);

            Ok(())
        })
    }

    #[test]
    fn unlock_ser_deser() -> Result<(), Error> {
        eeprom_scope(|| {
            let mut nonce = EEPROMVar::<NonceID>::new::<0x0>();
            let mut key = EEPROMVar::<Key>::new::<0x100>();
            let mut dummy_nonce = IncrementingNonceGenerator::new(nonce);
            let mut rng = CryptoRNG::new([0; 32]);

            let msg = UnlockMessage {
                id: CarID::new(123),
                passwd: Password::new([0u8; 32]),
            };

            let msg_c = msg.clone();

            let nonce = dummy_nonce.generate_nonce(&mut rng).unwrap();

            let packet = Packet::<Prepared>::new(&mut rng, msg).unwrap();

            let key_secret = Secret::new(key.read());

            let packet = packet.encrypt(&key_secret, nonce).unwrap();

            let packet = packet.decrypt(&key_secret).unwrap();

            let msg_2 = packet.to_message().unwrap();

            assert_eq!(msg_c, msg_2);

            Ok(())
        })
    }

    #[test]
    fn start_ser_deser() -> Result<(), Error> {
        eeprom_scope(|| {
            let mut nonce = EEPROMVar::<NonceID>::new::<0x0>();
            let mut key = EEPROMVar::<Key>::new::<0x100>();
            let mut dummy_nonce = IncrementingNonceGenerator::new(nonce);
            let mut rng = CryptoRNG::new([0; 32]);

            let msg = StartMessage {
                id: CarID::new(123),
                num_features: 2,
            };

            let msg_c = msg.clone();

            let nonce = dummy_nonce.generate_nonce(&mut rng).unwrap();

            let packet = Packet::<Prepared>::new(&mut rng, msg).unwrap();

            let key_secret = Secret::new(key.read());

            let packet = packet.encrypt(&key_secret, nonce).unwrap();

            let packet = packet.decrypt(&key_secret).unwrap();

            let msg_2 = packet.to_message().unwrap();

            assert_eq!(msg_c, msg_2);

            Ok(())
        })
    }

    // #[test]
    // fn enable_ser_deser() -> Result<(), PAREDError> {
    //     eeprom_scope(|| {
    //         let mut nonce = EEPROMVar::<NonceID>::new::<0x0>();
    //         let mut key = EEPROMVar::<Key>::new::<0x100>();
    //         let mut dummy_nonce = IncrementingNonceGenerator::new(nonce);
    //         let mut rng = CryptoRNG::new([0; 32]);

    //         let msg = EnableFeatureMessage {
    //             id: CarID::new(123),
    //             num: FeatureNumber::new(195),
    //         };

    //         let msg_c = msg.clone();

    //         let nonce = dummy_nonce.generate_nonce(&mut rng).unwrap();

    //         let packet = Packet::<Prepared>::new(&mut rng, msg).unwrap();

    //         let key_secret = Secret::new(key.read());

    //         let packet = packet.encrypt(&key_secret, nonce).unwrap();

    //         let packet = packet.decrypt(&key_secret).unwrap();

    //         let msg_2 = packet.to_message().unwrap();

    //         assert_eq!(msg_c, msg_2);

    //         Ok(())
    //     })
    // }

    #[test]
    fn pair_info_ser_deser() -> Result<(), Error> {
        eeprom_scope(|| {
            let mut nonce = EEPROMVar::<NonceID>::new::<0x0>();
            let mut key = EEPROMVar::<Key>::new::<0x100>();
            let mut dummy_nonce = IncrementingNonceGenerator::new(nonce);
            let mut rng = CryptoRNG::new([0; 32]);

            let msg = PairingFobInfoMessage {
                car_id: CarID::new(123),
                fob_id: [0x11u8; 32],
                extension_nonce: [0x22u8; 24],
                salt: [0x33u8; 16]
                // id: CarID::new(123),
                // passwd: Password::new([0u8; 32]),
                // pin: Pin::new([b'A', b'B', b'C', b'D', b'E', b'F', b'\x00', b'\x00']).unwrap(),
                // car_key: Key::new(*b"StreamMidnightsByTaylorSwift!!!!"),
            };

            let msg_c = msg.clone();

            let nonce = dummy_nonce.generate_nonce(&mut rng).unwrap();

            let packet = Packet::<Prepared>::new(&mut rng, msg).unwrap();

            let key_secret = Secret::new(key.read());

            let packet = packet.encrypt(&key_secret, nonce).unwrap();

            let packet = packet.decrypt(&key_secret).unwrap();

            let msg_2 = packet.to_message().unwrap();

            assert_eq!(msg_c, msg_2);

            Ok(())
        })
    }

    #[test]
    fn packet_send_recv() {
        eeprom_scope(|| {
            let mut nonce = EEPROMVar::<NonceID>::new::<0x0>();
            let mut key = EEPROMVar::<Key>::new::<0x100>();
            let mut dummy_nonce = IncrementingNonceGenerator::new(nonce);
            let mut rng = CryptoRNG::new([0; 32]);
            let mut io = DummyIO::new();

            let msg = PairRequestMessage {
                pin: Pin::new(*b"DEADBE").unwrap(),
            };
            let msg_c = msg.clone();

            let nonce = dummy_nonce.generate_nonce(&mut rng).unwrap();

            let packet = Packet::<Prepared>::new(&mut rng, msg).unwrap();

            let key_secret = Secret::new(key.read());

            let packet = packet.encrypt(&key_secret, nonce).unwrap();

            io.write_packet(packet);

            let recv_packet = unsafe { io.read_packet() }.verify(nonce).unwrap();

            let recv_packet = recv_packet.decrypt(&key_secret).unwrap();

            let msg_2 = recv_packet.to_message().unwrap();

            assert_eq!(msg_c, msg_2);
        })
    }

    #[test]
    #[should_panic]
    fn wrong_nonce() {
        let mut io = DummyIO::new();

        eeprom_scope(|| {
            let mut nonce = EEPROMVar::<NonceID>::new::<0x0>();
            nonce.write(&NonceID::from(0u32));
            let mut key = EEPROMVar::<Key>::new::<0x100>();

            let mut dummy_nonce = IncrementingNonceGenerator::new(nonce);

            let mut rng = CryptoRNG::new([0; 32]);

            let msg = PairRequestMessage {
                pin: Pin::new(*b"DEADBE").unwrap(),
            };

            let nonce = dummy_nonce.generate_nonce(&mut rng).unwrap();

            let packet = Packet::<Prepared>::new(&mut rng, msg).unwrap();

            let key_secret = Secret::new(key.read());

            let packet = packet.encrypt(&key_secret, nonce).unwrap();

            io.write_packet(packet);
        });

        let _recv_packet = unsafe { io.read_packet() }
            .verify(*Nonce::from_slice(&[0u8; 24]))
            .unwrap();
    }
}
