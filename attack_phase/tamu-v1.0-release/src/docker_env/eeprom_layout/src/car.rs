use crate::{impl_primitive, Hash, Hashed, Primitive};
use core::mem::size_of;
use memoffset::offset_of;

pub struct BeforePad {
    pub text_hash: TextHash,
    pub paired_pubkey: Hashed<PairedPubKey>,
    pub car_auth_privkey: Hashed<CarAuthPrivKey>,
    pub seed: Hashed<CarSeed>,
}

pub const FEATURE_START: usize = 0x700;
pub const PAD: usize = FEATURE_START - size_of::<BeforePad>();

#[repr(C, align(4))]
pub struct CarLayout {
    pub before_pad: BeforePad,
    pub _pad: [u8; PAD],
    pub feature3: Feature3,
    pub feature2: Feature2,
    pub feature1: Feature1,
    pub unlock: Unlock,
}

sa::const_assert_eq!(offset_of!(CarLayout, feature3), 0x700);
sa::const_assert_eq!(offset_of!(CarLayout, feature2), 0x740);
sa::const_assert_eq!(offset_of!(CarLayout, feature1), 0x780);
sa::const_assert_eq!(offset_of!(CarLayout, unlock), 0x7C0);

#[repr(C, align(4))]
pub struct TextHash(pub Hash);
#[repr(C, align(4))]
pub struct PairedPubKey(pub super::PubKey);
#[repr(C, align(4))]
pub struct CarAuthPrivKey(pub super::PrivKey);
#[repr(C, align(4))]
pub struct CarSeed(pub super::Seed);
#[repr(C, align(4))]
pub struct Feature3(pub [u8; 64]);
#[repr(C, align(4))]
pub struct Feature2(pub [u8; 64]);
#[repr(C, align(4))]
pub struct Feature1(pub [u8; 64]);
#[repr(C, align(4))]
pub struct Unlock(pub [u8; 64]);

impl_primitive!(offset_of!(BeforePad, text_hash), TextHash);
impl_primitive!(offset_of!(BeforePad, paired_pubkey), PairedPubKey);
impl_primitive!(offset_of!(BeforePad, car_auth_privkey), CarAuthPrivKey);
impl_primitive!(offset_of!(BeforePad, seed), CarSeed);
impl_primitive!(0, CarLayout);
impl_primitive!(offset_of!(CarLayout, feature3), Feature3);
impl_primitive!(offset_of!(CarLayout, feature2), Feature2);
impl_primitive!(offset_of!(CarLayout, feature1), Feature1);
impl_primitive!(offset_of!(CarLayout, unlock), Unlock);
