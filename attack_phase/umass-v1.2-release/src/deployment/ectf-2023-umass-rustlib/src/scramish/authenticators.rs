use sha2::Sha256;
use hmac::Mac;
use sha2::Digest;

use subtle::ConstantTimeEq;

use crate::scramish::HmacSha256;
use crate::scramish::{SALTED_PWD_LEN, SHA256_OUT_LEN};

use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicBool, Ordering};

pub(crate) const MEM_BLOCK_COUNT: usize = 17;

static mut MEM_BLOCKS: [MaybeUninit<argon2::Block>; MEM_BLOCK_COUNT] = unsafe {MaybeUninit::uninit().assume_init()};
static HASHING_PWD: AtomicBool = AtomicBool::new(false);

// Note: tests should pass in mem block to avoid mutex on static MEM_BLOCKS
pub fn hash_pwd(pwd: &[u8], salt: &[u8], mem_blocks: Option<&mut [argon2::Block; MEM_BLOCK_COUNT]>) -> [u8; SALTED_PWD_LEN] {
    let mut out = [0x00; SALTED_PWD_LEN];
    // Argon2 parameters set at compile time and checked to be valid
    let argon2 = argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(MEM_BLOCK_COUNT.try_into().unwrap(), 104, 1, Some(SALTED_PWD_LEN)).unwrap()
    );
    #[cfg(test)]
    assert!(mem_blocks.is_some());

    // Memory requirements = memory cost = MEM_BLOCK_COUNT
    // mem_blocks is guaranteed to have enough space
    match mem_blocks {
        Some(mem) => argon2.hash_password_into_with_memory(pwd, salt, &mut out, mem).unwrap(),
        None => {
            // Assert that we aren't running two hashings concurrently
            // Impossible on the real board, only possible with incorrect tests
            assert!(!HASHING_PWD.swap(true, Ordering::SeqCst));
            // As per MaybeUninit documentation, initialize each element and then transmute
            let mem_blocks_ref = unsafe {
                for maybeuninit_block in &mut MEM_BLOCKS {
                    maybeuninit_block.write(argon2::Block::default());
                }
                // We are transmuting a live reference (-> NonNull), so as_mut() is Some()
                (&mut MEM_BLOCKS as *mut [MaybeUninit<argon2::Block>; MEM_BLOCK_COUNT]
                    as *mut [argon2::Block; MEM_BLOCK_COUNT]).as_mut().unwrap()
            };
            argon2.hash_password_into_with_memory(pwd, salt, &mut out, mem_blocks_ref).unwrap();
            HASHING_PWD.store(false, Ordering::SeqCst);
        }
    };
    out
}
fn xor_arr<const N: usize>(arr1: impl Into<[u8; N]>, arr2: impl Into<[u8; N]>) -> [u8; N] {
    let arr1 = arr1.into();
    let arr2 = arr2.into();
    let mut arr_out = [0x00; N];
    for i in 0..N {
        arr_out[i] = arr1[i] ^ arr2[i];
    }
    arr_out
}

pub fn client_key(salted_pwd: [u8; SALTED_PWD_LEN]) -> [u8; SHA256_OUT_LEN] {
    let mut hmac_clientkey = HmacSha256::new_from_slice(&salted_pwd).unwrap();
    hmac_clientkey.update(b"Client Key");
    let client_key = hmac_clientkey.finalize().into_bytes();
    client_key.into()
}

pub fn client_proof(salted_pwd: [u8; SALTED_PWD_LEN], auth: &[u8]) -> [u8; SHA256_OUT_LEN] {
    let client_key = client_key(salted_pwd);

    let h_client_key = Sha256::digest(client_key);

    let mut hmac_clientproof = HmacSha256::new_from_slice(&h_client_key).unwrap();
    hmac_clientproof.update(auth);
    let client_proof_hmac = hmac_clientproof.finalize().into_bytes();

    let client_proof = xor_arr(client_proof_hmac, client_key);
    client_proof
}

pub fn client_proof_verify(h_client_key: [u8; SHA256_OUT_LEN], auth: &[u8], recv_proof: [u8; SHA256_OUT_LEN]) -> Option<[u8; SHA256_OUT_LEN]> {

    let mut hmac_clientproof = HmacSha256::new_from_slice(&h_client_key).unwrap();
    hmac_clientproof.update(auth);
    let client_proof_hmac = hmac_clientproof.finalize().into_bytes();

    let recv_client_key = xor_arr(recv_proof, client_proof_hmac);
    let recv_h_client_key = Sha256::digest(recv_client_key);
    if recv_h_client_key.ct_eq(&h_client_key).into() {
        Some(protocol_key(recv_client_key, auth))
    } else {
        None
    }
}
pub fn server_key(salted_pwd: [u8; SALTED_PWD_LEN]) -> [u8; SHA256_OUT_LEN] {
    let mut hmac_serverkey = HmacSha256::new_from_slice(&salted_pwd).unwrap();
    hmac_serverkey.update(b"Server Key");
    let server_key = hmac_serverkey.finalize().into_bytes();
    server_key.into()
}
pub fn server_sig(server_key: [u8; SHA256_OUT_LEN], auth: &[u8]) -> [u8; SHA256_OUT_LEN] {
    let mut hmac_serversig = HmacSha256::new_from_slice(&server_key).unwrap();
    hmac_serversig.update(auth);
    let server_sig = hmac_serversig.finalize().into_bytes();
    server_sig.into()
}
pub fn protocol_key(client_key: [u8; SHA256_OUT_LEN], auth: &[u8]) -> [u8; SHA256_OUT_LEN] {
    let h_client_key = Sha256::digest(client_key);
    let mut hmac_protocol_key = HmacSha256::new_from_slice(&h_client_key).unwrap();
    hmac_protocol_key.update(b"PARED session key");
    hmac_protocol_key.update(&client_key);
    hmac_protocol_key.update(auth);
    let protocol_key = hmac_protocol_key.finalize().into_bytes();
    protocol_key.into()
}
