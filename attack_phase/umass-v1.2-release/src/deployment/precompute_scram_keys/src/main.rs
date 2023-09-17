#![forbid(unsafe_code)]
use std::env::args;

use hex::decode;

use serde::Serialize;
use serde_hex::{SerHex, StrictCap};
use serde_json::to_string as to_json_string;

use sha2::{Sha256, Digest};

use hmac::{Hmac, Mac};
pub type HmacSha256 = Hmac<Sha256>;

const SHA256_OUT_LEN: usize = 32;
const SALTED_PWD_LEN: usize = 36;

const MEM_BLOCK_COUNT: u32 = 17;

pub fn hash_pwd(pwd: &[u8], salt: &[u8]) -> [u8; SALTED_PWD_LEN] {
    let mut out = [0x00; SALTED_PWD_LEN];
    let argon2 = argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(MEM_BLOCK_COUNT, 104, 1, Some(SALTED_PWD_LEN)).unwrap()
    );
    argon2.hash_password_into(pwd, salt, &mut out).unwrap();
    out
}

fn client_key(salted_pwd: [u8; SALTED_PWD_LEN]) -> [u8; SHA256_OUT_LEN] {
    let mut hmac_clientkey = HmacSha256::new_from_slice(&salted_pwd).unwrap();
    hmac_clientkey.update(b"Client Key");
    let client_key = hmac_clientkey.finalize().into_bytes();
    client_key.into()
}
fn server_key(salted_pwd: [u8; SALTED_PWD_LEN]) -> [u8; SHA256_OUT_LEN] {
    let mut hmac_serverkey = HmacSha256::new_from_slice(&salted_pwd).unwrap();
    hmac_serverkey.update(b"Server Key");
    let server_key = hmac_serverkey.finalize().into_bytes();
    server_key.into()
}

// Copy from actual SCRAMish code
#[derive(Debug, Serialize)]
pub struct ScramishServerHmacs {
    #[serde(with = "SerHex::<StrictCap>")]
    h_clientkey: [u8; SHA256_OUT_LEN],
    #[serde(with = "SerHex::<StrictCap>")]
    serverkey: [u8; SHA256_OUT_LEN]
}

fn main() -> Result<(), String> {
    let arg_vec: Vec<_> = args().collect();
    if arg_vec.len() != 3 {
        return Err("Usage: precompute_scram_keys pwd_hex salt_hex".to_owned());
    }

    let pwd_hex = &arg_vec[1];
    if pwd_hex.len() % 2 != 0 {
        return Err("pwd_hex len must be even".to_owned());
    }
    let salt_hex = &arg_vec[2];
    if salt_hex.len() % 2 != 0 {
        return Err("salt_hex len must be even".to_owned());
    }

    let pwd = decode(pwd_hex).map_err(|e| format!("{}", e))?;
    let salt = decode(salt_hex).map_err(|e| format!("{}", e))?;

    let salted_pwd = hash_pwd(&pwd, &salt);
    let h_client_key = Sha256::digest(client_key(salted_pwd));
    let server_key = server_key(salted_pwd);
    let hmacs = ScramishServerHmacs { h_clientkey: h_client_key.into(), serverkey: server_key };
    print!("{}", to_json_string(&hmacs).map_err(|e| format!("{}", e))?);
    Ok(())
}
