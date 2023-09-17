extern crate static_assertions as sa;
use blake2::{Blake2s256, Digest};
use eeprom_layout::{
    fob::{CarId, FeatureFlags, PackagePubKey},
    impl_primitive, EnablePackage, Primitive,
};
use p256::ecdsa::{signature::Verifier, Signature};
use pared_core::crypto::{jitter, BlakeHash};
use pared_core::error::{Error, Result};
use pared_core::peripherals::Peripherals;
use rand_chacha::ChaChaRng;

#[repr(C, align(4))]
struct FeaturePackage {
    car_id: u32,
    feature_number: u32,
    hash: BlakeHash,
    signature: Signature,
}
impl_primitive!(0, FeaturePackage);

pub fn enable_feature(p: &mut Peripherals, r: &mut ChaChaRng) -> Result<()> {
    let verifying_key = p.eeprom.load_hashed::<PackagePubKey>(r)?.0.load();
    let car_id = p.eeprom.load_hashed::<CarId>(r)?.0;
    let mut feature_flags = p.eeprom.load_hashed::<FeatureFlags>(r)?;

    let package = {
        let mut package = EnablePackage::zeroed();
        p.uart_ht
            .ready_nonblocking_read_exact(package.as_bytes_mut())?;
        package
    };

    let hash = {
        let mut hasher = Blake2s256::new();
        hasher.update(&package.car_id.to_le_bytes());
        hasher.update(&package.feature_number.to_le_bytes());
        hasher.finalize()
    };

    jitter(r);
    verifying_key.verify(&package.hash, &package.signature)?;

    if hash != package.hash {
        return Err(Error::InvalidHash);
    }

    if package.car_id != car_id {
        return Err(Error::InvalidCarId);
    }

    *feature_flags
        .0
        .get_mut(package.feature_number as usize - 1)
        .ok_or(Error::InvalidRegion)? = true;
    p.eeprom.store_hashed::<FeatureFlags>(feature_flags)
}
