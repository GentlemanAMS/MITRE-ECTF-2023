use eeprom_layout::fob::{CarAuthPubKey, FeatureFlags, PairedPrivKey};
use pared_core::error::Result;
use pared_core::peripherals::Peripherals;
use rand_chacha::ChaChaRng;

use crate::crypto::{Responder, TwoWay};

pub fn unlock(p: &mut Peripherals, r: &mut ChaChaRng) -> Result<()> {
    let enabled_features = p.eeprom.load_hashed::<FeatureFlags>(r)?;
    let responder = TwoWay::new(
        p.eeprom.load_hashed::<PairedPrivKey>(r)?.0.load(),
        p.eeprom.load_hashed::<CarAuthPubKey>(r)?.0.load(),
    );
    p.uart_board.write_all(b"U");
    Responder::auth_with_data(&responder, p, r, &enabled_features.0.map(|x| x as u8))
}
