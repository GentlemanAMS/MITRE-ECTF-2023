mod authenticators;
mod scramish_structs;

use crate::packet_types::PacketCore;

pub use authenticators::{hash_pwd, client_key, server_key};
use authenticators::{client_proof, client_proof_verify, server_sig, protocol_key};
use authenticators::MEM_BLOCK_COUNT;
use scramish_structs::*;

pub use scramish_structs::{CLIENT_FIRST_LEN, SERVER_FIRST_LEN, CLIENT_FINISH_LEN, SERVER_FINISH_LEN, SHA256_OUT_LEN, SALT_LEN};

use subtle::ConstantTimeEq;

use rand_core::RngCore;
use heapless::Vec;
use sha2::Sha256;
use sha2::Digest;

use hmac::Hmac;
pub type HmacSha256 = Hmac<Sha256>;

#[derive(Debug)]
pub struct ScramishServerHmacs {
    h_clientkey: [u8; SHA256_OUT_LEN],
    serverkey: [u8; SHA256_OUT_LEN]
}
impl ScramishServerHmacs {
    #[inline(always)]
    pub fn h_clientkey(&self) -> [u8; SHA256_OUT_LEN] {
        self.h_clientkey
    }
    #[inline(always)]
    pub fn serverkey(&self) -> [u8; SHA256_OUT_LEN] {
        self.serverkey
    }

    pub fn new(h_clientkey: [u8; SHA256_OUT_LEN], serverkey: [u8; SHA256_OUT_LEN]) -> Self {
        Self { h_clientkey, serverkey }
    }
    pub fn from_pwd_and_salt(pwd: &[u8], salt: &[u8], mem_blocks: Option<&mut [argon2::Block; MEM_BLOCK_COUNT]>) -> ScramishServerHmacs {
        let salted_pwd = hash_pwd(pwd, salt, mem_blocks);
        let h_clientkey = Sha256::digest(client_key(salted_pwd)).into();
        let serverkey = server_key(salted_pwd);

        ScramishServerHmacs { h_clientkey, serverkey }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScramishError {
    CnonceMismatch,
    SnonceMismatch,
    InvalidClientProof,
    InvalidServerSig
}
// For normal std, we would derive std::error::Error

#[derive(Debug)]
pub struct ScramishServer {
    snonce: [u8; NONCE_LEN],
    recv_cnonce: Option<[u8; NONCE_LEN]>,
    auth: Vec<u8, SCRAMISH_AUTH_LEN>,
    salt: [u8; SALT_LEN],
    pwdish_storage: Option<ScramishServerHmacs>
}
impl ScramishServer {
    pub fn with_rng<R: RngCore+?Sized>(rng: &mut R) -> ScramishServer {
        let mut snonce = [0x00; NONCE_LEN];
        rng.fill_bytes(&mut snonce);
        let mut salt = [0x00; SALT_LEN];
        rng.fill_bytes(&mut salt);
        ScramishServer { snonce, recv_cnonce: None,
            auth: Vec::new(),
            salt,
            pwdish_storage: None }
    }
    pub fn with_rng_and_pwd_storage<R: RngCore+?Sized>(rng: &mut R, salt: [u8; SALT_LEN], pwd_storage: ScramishServerHmacs) -> ScramishServer {
        let mut snonce = [0x00; NONCE_LEN];
        rng.fill_bytes(&mut snonce);
        ScramishServer { snonce, recv_cnonce: None,
            auth: Vec::new(),
            salt,
            pwdish_storage: Some(pwd_storage) }
    }
    pub fn handle_client_first(&mut self, client_first: [u8; CLIENT_FIRST_LEN]) -> (u32, [u8; SERVER_FIRST_LEN]) {
        self.auth.extend(client_first);
        let client_first_msg = ClientFirstMsg::deserialize(client_first);
        self.recv_cnonce = Some(client_first_msg.cnonce());

        let server_first = ServerFirstMsg::new(
            client_first_msg.cnonce(),
            self.snonce,
            self.salt
        );

        let out = server_first.serialize();
        self.auth.extend(out);

        let uid = client_first_msg.uid();
        (uid, out)
    }
    pub fn emplace_salted_pwd(&mut self, pwd: &[u8], mem_blocks: Option<&mut [argon2::Block; MEM_BLOCK_COUNT]>) {
        // This function is only called once per object
        assert!(self.pwdish_storage.is_none());
        self.pwdish_storage = Some(ScramishServerHmacs::from_pwd_and_salt(pwd, &self.salt, mem_blocks));
    }
    pub fn handle_client_final(mut self, client_final: [u8; CLIENT_FINISH_LEN]) -> Result<([u8; SERVER_FINISH_LEN], [u8; SHA256_OUT_LEN]), ScramishError> {
        let client_final_msg = ClientFinalMsg::deserialize(client_final);
        // recv_cnonce must have been set during handle_client_first()
        if client_final_msg.cnonce() != self.recv_cnonce.unwrap() {
            return Err(ScramishError::CnonceMismatch);
        }
        if client_final_msg.snonce() != self.snonce {
            return Err(ScramishError::SnonceMismatch);
        }
        let client_final_without_proof = client_final_msg.serialize_without_proof();
        self.auth.extend(client_final_without_proof);

        // Assert that we appended exactly the right number of items
        // Would only fail if methods called out of order
        assert_eq!(self.auth.len(), SCRAMISH_AUTH_LEN);

        // self.pwdish_storage set during emplace_salted_pwd()
        // (which should have been called before)
        // or from with_rng_and_pwd_storage() object construction
        let client_proof_valid = client_proof_verify(self.pwdish_storage.as_ref().unwrap().h_clientkey, &self.auth, client_final_msg.proof());
        if let Some(protocol_key) = client_proof_valid {
            let server_sig = server_sig(self.pwdish_storage.as_ref().unwrap().serverkey, &self.auth);
            Ok((server_sig, protocol_key))
        } else {
            Err(ScramishError::InvalidClientProof)
        }
    }
}

#[derive(Debug)]
pub struct ScramishClient {
    cnonce: [u8; NONCE_LEN],
    auth: Vec<u8, SCRAMISH_AUTH_LEN>,
    salt: Option<[u8; SALT_LEN]>,
    salted_pwd: Option<[u8; SALTED_PWD_LEN]>
}
impl ScramishClient {
    // Getters are only called after handle_server_first
    #[inline(always)]
    pub fn salted_password(&self) -> [u8; SALTED_PWD_LEN] {
        self.salted_pwd.unwrap()
    }
    #[inline(always)]
    pub fn salt(&self) -> [u8; SALT_LEN] {
        self.salt.unwrap()
    }

    pub fn with_rng<R: RngCore+?Sized>(rng: &mut R) -> ScramishClient {
        let mut cnonce = [0x00; NONCE_LEN];
        rng.fill_bytes(&mut cnonce);
        ScramishClient { cnonce, auth: Vec::new(), salt: None, salted_pwd: None }
    }
    pub fn client_first(&mut self, uid: u32) -> [u8; CLIENT_FIRST_LEN] {
        let client_first = ClientFirstMsg::new(uid, self.cnonce);
        let out = client_first.serialize();
        self.auth.extend(out);
        out
    }
    pub fn handle_server_first(&mut self, pwd: &[u8], server_first: [u8; SERVER_FIRST_LEN], mem_blocks: Option<&mut [argon2::Block; MEM_BLOCK_COUNT]>) -> Result<[u8; CLIENT_FINISH_LEN], ScramishError> {
        let server_first_msg = ServerFirstMsg::deserialize(server_first);
        if server_first_msg.cnonce() != self.cnonce {
            return Err(ScramishError::CnonceMismatch);
        }
        self.auth.extend(server_first);

        let client_finish_partial = ClientFinalMsgPartial::new(self.cnonce, server_first_msg.snonce());
        self.auth.extend(client_finish_partial.serialize_without_proof());

        // Assert that we appended exactly the right number of items
        // Would only fail if methods called out of order
        assert_eq!(self.auth.len(), SCRAMISH_AUTH_LEN);

        self.salt = Some(server_first_msg.salt());
        self.salted_pwd = Some(hash_pwd(pwd, &server_first_msg.salt(), mem_blocks));
        let proof = client_proof(self.salted_pwd.unwrap(), &self.auth);

        let client_finish_msg = ClientFinalMsg::from_partial(client_finish_partial, proof);

        Ok(client_finish_msg.serialize())
    }
    pub fn handle_server_final(self, server_final: [u8; SERVER_FINISH_LEN]) -> Result<[u8; SHA256_OUT_LEN], ScramishError> {
        // self.salted_pwd set during handle_server_first
        let server_key = server_key(self.salted_pwd.unwrap());
        let computed_server_sig = server_sig(server_key, &self.auth);
        if computed_server_sig.ct_eq(&server_final).into() {
            let client_key = client_key(self.salted_pwd.unwrap());
            Ok(protocol_key(client_key, &self.auth))
        } else {
            Err(ScramishError::InvalidServerSig)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    extern crate std;
    use rand::thread_rng;

    #[test]
    fn test_success_w_pwd() {
        let uid = 444;
        let pwd = b"queer pride uwu";

        let mut pwd_scratch_space: Option<[argon2::Block; MEM_BLOCK_COUNT]> = Some([argon2::Block::default(); MEM_BLOCK_COUNT]);
        let mut rng = thread_rng();
        let mut client = ScramishClient::with_rng(&mut rng);
        let mut server = ScramishServer::with_rng(&mut rng);

        let client_first = client.client_first(uid);
        let (server_uid, server_first) = server.handle_client_first(client_first);
        assert_eq!(uid, server_uid);

        server.emplace_salted_pwd(pwd, pwd_scratch_space.as_mut());

        let client_final = client.handle_server_first(pwd, server_first, pwd_scratch_space.as_mut()).unwrap();
        let (server_final, server_protocol_key) = server.handle_client_final(client_final).unwrap();
        let client_protocol_key = client.handle_server_final(server_final).unwrap();

        //assert_eq!(client.auth, server.auth);

        assert_eq!(client_protocol_key, server_protocol_key);
    }
    #[test]
    fn test_success_w_precomputed() {
        let uid = 444;
        let pwd = b"trans rights :3";

        let mut pwd_scratch_space: Option<[argon2::Block; MEM_BLOCK_COUNT]> = Some([argon2::Block::default(); MEM_BLOCK_COUNT]);
        let mut rng = thread_rng();

        let mut server_salt = [0x00; SALT_LEN];
        rng.fill_bytes(&mut server_salt);

        let pwd_storage = ScramishServerHmacs::from_pwd_and_salt(pwd, &server_salt, pwd_scratch_space.as_mut());

        let mut client = ScramishClient::with_rng(&mut rng);
        let mut server = ScramishServer::with_rng_and_pwd_storage(&mut rng, server_salt, pwd_storage);

        let client_first = client.client_first(uid);
        let (server_uid, server_first) = server.handle_client_first(client_first);
        assert_eq!(uid, server_uid);

        let client_final = client.handle_server_first(pwd, server_first, pwd_scratch_space.as_mut()).unwrap();
        let (server_final, server_protocol_key) = server.handle_client_final(client_final).unwrap();
        let client_protocol_key = client.handle_server_final(server_final).unwrap();

        //assert_eq!(client.auth, server.auth);

        assert_eq!(client_protocol_key, server_protocol_key);
    }
    // Check what happens when an interposer modifies the cnonce
    #[test]
    fn test_failure_on_corrupt_cnonce() {
        let uid = 444;
        let pwd = b"be gay do cwime";

        let mut pwd_scratch_space: Option<[argon2::Block; MEM_BLOCK_COUNT]> = Some([argon2::Block::default(); MEM_BLOCK_COUNT]);
        let mut rng = thread_rng();
        
        for i in core::mem::size_of::<u32>()..CLIENT_FIRST_LEN {
            let mut client = ScramishClient::with_rng(&mut rng);
            let mut server = ScramishServer::with_rng(&mut rng);
    
            let mut client_first = client.client_first(uid);
            client_first[i] = !client_first[i];
            let (server_uid, mut server_first) = server.handle_client_first(client_first);
            assert_eq!(uid, server_uid);

            server.emplace_salted_pwd(pwd, pwd_scratch_space.as_mut());

            server_first[i-core::mem::size_of::<u32>()] = !server_first[i-core::mem::size_of::<u32>()];
    
            let mut client_final = client.handle_server_first(pwd, server_first, pwd_scratch_space.as_mut()).unwrap();
            client_final[i-core::mem::size_of::<u32>()] = !client_final[i-core::mem::size_of::<u32>()];
            let /*(server_final, server_protocol_key)*/ error = server.handle_client_final(client_final).unwrap_err();
            //let error = server.handle_client_final(client_final).unwrap_err();
            assert_eq!(error, ScramishError::InvalidClientProof);

            //let client_protocol_key = client.handle_server_final(server_final).unwrap();
    
            //assert_eq!(client.auth, server.auth);
        }
    }
    // Check what happens when an interposer modifies the snonce
    #[test]
    fn test_failure_on_corrupt_snonce() {
        let uid = 444;
        let pwd = b"bingle weed cat";

        let mut pwd_scratch_space: Option<[argon2::Block; MEM_BLOCK_COUNT]> = Some([argon2::Block::default(); MEM_BLOCK_COUNT]);
        let mut rng = thread_rng();
        
        for i in 0..NONCE_LEN {
            let mut client = ScramishClient::with_rng(&mut rng);
            let mut server = ScramishServer::with_rng(&mut rng);
    
            let client_first = client.client_first(uid);
            let (server_uid, mut server_first) = server.handle_client_first(client_first);
            assert_eq!(uid, server_uid);

            server.emplace_salted_pwd(pwd, pwd_scratch_space.as_mut());

            server_first[i+NONCE_LEN] = !server_first[i+NONCE_LEN];
    
            let mut client_final = client.handle_server_first(pwd, server_first, pwd_scratch_space.as_mut()).unwrap();
            client_final[i+NONCE_LEN] = !client_final[i+NONCE_LEN];
            let /*(server_final, server_protocol_key)*/ error = server.handle_client_final(client_final).unwrap_err();
            //let error = server.handle_client_final(client_final).unwrap_err();
            assert_eq!(error, ScramishError::InvalidClientProof);

            //let client_protocol_key = client.handle_server_final(server_final).unwrap();
    
            //assert_eq!(client.auth, server.auth);
        }
    }
}
