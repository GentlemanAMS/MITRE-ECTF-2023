use crate::{impl_primitive, Hash, Hashed, Primitive};
use memoffset::offset_of;

#[repr(C)]
pub struct FobLayout {
    pub text_hash: TextHash,
    pub seed: Hashed<FobSeed>,
    pub manufacturer_pubkey: Hashed<ManufacturerPubKey>,
    pub manufacturer_privkey: Hashed<ManufacturerPrivKey>,
    pub package_pubkey: Hashed<PackagePubKey>,
    pub fob_symmetric: Hashed<FobSymmetric>,
    pub feature_flags: Hashed<FeatureFlags>,
    pub timeout: Hashed<Timeout>,
    pub car_auth_pubkey: Hashed<CarAuthPubKey>,
    pub paired_privkey: Hashed<PairedPrivKey>,
    pub pin_hash: PinHash,
    pub car_id: Hashed<CarId>,
}

#[repr(C, align(4))]
pub struct TextHash(pub Hash);
#[repr(C, align(4))]
pub struct ManufacturerPubKey(pub super::PubKey);
#[repr(C, align(4))]
pub struct ManufacturerPrivKey(pub super::PrivKey);
#[repr(C, align(4))]
pub struct PackagePubKey(pub super::PubKey);
#[repr(C, align(4))]
pub struct CarAuthPubKey(pub super::PubKey);
#[repr(C, align(4))]
pub struct PairedPrivKey(pub super::PrivKey);
#[repr(C, align(4))]
pub struct PinHash(pub Hash);
#[repr(C, align(4))]
pub struct FobSymmetric(pub [u8; 32]);
#[repr(C, align(4))]
pub struct CarId(pub u32);
#[repr(C, align(4))]
pub struct Timeout(pub u32);
#[repr(C, align(4))]
pub struct FobSeed(pub super::Seed);
#[repr(C, align(4))]
pub struct FeatureFlags(pub [bool; 4]);

impl_primitive!(0, FobLayout);
impl_primitive!(offset_of!(FobLayout, text_hash), TextHash);
impl_primitive!(offset_of!(FobLayout, manufacturer_pubkey), ManufacturerPubKey);
impl_primitive!(offset_of!(FobLayout, manufacturer_privkey), ManufacturerPrivKey);
impl_primitive!(offset_of!(FobLayout, package_pubkey), PackagePubKey);
impl_primitive!(offset_of!(FobLayout, car_auth_pubkey), CarAuthPubKey);
impl_primitive!(offset_of!(FobLayout, paired_privkey), PairedPrivKey);
impl_primitive!(offset_of!(FobLayout, pin_hash), PinHash);
impl_primitive!(offset_of!(FobLayout, fob_symmetric), FobSymmetric);
impl_primitive!(offset_of!(FobLayout, car_id), CarId);
impl_primitive!(offset_of!(FobLayout, timeout), Timeout);
impl_primitive!(offset_of!(FobLayout, seed), FobSeed);
impl_primitive!(offset_of!(FobLayout, feature_flags), FeatureFlags);
