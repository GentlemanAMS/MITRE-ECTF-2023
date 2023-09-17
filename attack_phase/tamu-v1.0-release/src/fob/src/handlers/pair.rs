extern crate static_assertions as sa;
use core::mem::size_of;

use chacha20poly1305::{Tag, XNonce};
use eeprom_layout::fob::{
    CarAuthPubKey, CarId, FobSymmetric, PairedPrivKey,
    PinHash, Timeout,
};
use eeprom_layout::{impl_primitive, Primitive};
use pared_core::crypto::{generate_nonce, oneshot_decrypt, oneshot_encrypt, verify_hash};
use pared_core::error::Result;
use pared_core::peripherals::Peripherals;
use rand_chacha::ChaChaRng;

#[repr(C, align(4))]
struct PairingSecrets {
    car_id: CarId,
    car_auth_pubkey: CarAuthPubKey,
    paired_privkey: PairedPrivKey,
    pin_hash: PinHash
}
impl_primitive!(0, PairingSecrets);

pub fn pairer(p: &mut Peripherals, r: &mut ChaChaRng) -> Result<()> {
    let fob_key = p.eeprom.load_hashed::<FobSymmetric>(r)?.0;
    let pin_hash = p.eeprom.load::<PinHash>()?.0;
    
    let pin = p
        .uart_ht
        .ready_nonblocking_read_arr::<{ size_of::<u32>() }>()?;

    p.eeprom.store_hashed::<Timeout>(Timeout(230_000_000))?;

    verify_hash(&pin, &pin_hash, r)?;

    p.eeprom.store_hashed::<Timeout>(Timeout(0))?;

    let mut pairing_secrets = PairingSecrets {
        car_id: p.eeprom.load_hashed::<CarId>(r)?,
        car_auth_pubkey: p.eeprom.load_hashed::<CarAuthPubKey>(r)?,
        paired_privkey: p.eeprom.load_hashed::<PairedPrivKey>(r)?,
        pin_hash: p.eeprom.load::<PinHash>()?
    };

    let nonce = generate_nonce(r);
    let tag = oneshot_encrypt(
        pairing_secrets.as_bytes_mut(),
        &fob_key.into(),
        &nonce.into(),
    )?;

    p.uart_ht.write_all(pairing_secrets.as_bytes());
    p.uart_ht.write_all(&tag);
    p.uart_ht.write_all(&nonce);

    p.uart_board.ready_write_all(pairing_secrets.as_bytes())?;
    p.uart_board.ready_write_all(&tag)?;
    p.uart_board.ready_write_all(&nonce)?;
    Ok(())
}

pub fn pairee(p: &mut Peripherals, r: &mut ChaChaRng) -> Result<()> {
    let fob_key = p.eeprom.load_hashed::<FobSymmetric>(r)?.0;

    let pairing_secrets = {
        let mut ret = PairingSecrets::zeroed();
        p.uart_board
            .ready_nonblocking_read_exact(ret.as_bytes_mut())?;
        let tag = p
            .uart_board
            .ready_nonblocking_read_arr::<{ size_of::<Tag>() }>()?;
        let nonce = p
            .uart_board
            .ready_nonblocking_read_arr::<{ size_of::<XNonce>() }>()?;
        
        p.uart_ht.write_all(ret.as_bytes());
        p.uart_ht.write_all(&tag);
        p.uart_ht.write_all(&nonce);
        
        oneshot_decrypt(
            ret.as_bytes_mut(),
            &fob_key.into(),
            &tag.into(),
            &nonce.into(),
        )?;
        ret
    };

    p.eeprom.store_hashed::<CarId>(pairing_secrets.car_id)?;
    p.eeprom
        .store_hashed::<CarAuthPubKey>(pairing_secrets.car_auth_pubkey)?;
    p.eeprom
        .store_hashed::<PairedPrivKey>(pairing_secrets.paired_privkey)?;
    p.eeprom.store::<PinHash>(&pairing_secrets.pin_hash)?;

    Ok(())
}
