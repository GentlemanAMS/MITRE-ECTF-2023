use crate::packet_types::PacketCore;

// Offset all the lengths slightly during development to ensure errors on length mismatches
pub const SHA256_OUT_LEN: usize = 32;
pub(crate) const NONCE_LEN: usize = 28;
pub const SALT_LEN: usize = 16;
pub(crate) const SALTED_PWD_LEN: usize = 36;

pub const CLIENT_FIRST_LEN: usize = core::mem::size_of::<u32>() + NONCE_LEN;
pub const SERVER_FIRST_LEN: usize = 2*NONCE_LEN+SALT_LEN;
pub const PROOF_LEN: usize = SHA256_OUT_LEN;
pub const CLIENT_FINISH_LEN: usize = 2*NONCE_LEN+PROOF_LEN;
pub const SERVER_FINISH_LEN: usize = SHA256_OUT_LEN;
pub const SCRAMISH_AUTH_LEN: usize = CLIENT_FIRST_LEN+SERVER_FIRST_LEN+2*NONCE_LEN;

#[derive(Debug)]
pub struct ClientFirstMsg {
    uid: u32,
    cnonce: [u8; NONCE_LEN]
}
impl ClientFirstMsg {
    pub(crate) fn new(uid: u32, cnonce: [u8; NONCE_LEN]) -> Self {
        Self { uid, cnonce }
    }
    #[inline(always)]
    pub fn uid(&self) -> u32 {
        self.uid
    }
    #[inline(always)]
    pub fn cnonce(&self) -> [u8; NONCE_LEN] {
        self.cnonce
    }
}
impl PacketCore<CLIENT_FIRST_LEN> for ClientFirstMsg {
    fn serialize(&self) -> [u8; CLIENT_FIRST_LEN] {
        let mut out = [0x00; CLIENT_FIRST_LEN];
        let uid_bytes = self.uid.to_be_bytes();
        out[..core::mem::size_of::<u32>()].copy_from_slice(&uid_bytes);
        out[core::mem::size_of::<u32>()..].copy_from_slice(&self.cnonce);
        out
    }
    fn deserialize(data: [u8; CLIENT_FIRST_LEN]) -> Self {
        Self {
            uid: u32::from_be_bytes(data[..core::mem::size_of::<u32>()].try_into().unwrap()),
            cnonce: data[core::mem::size_of::<u32>()..].try_into().unwrap()
        }
    }
}

#[derive(Debug)]
pub struct ServerFirstMsg {
    cnonce: [u8; NONCE_LEN],
    snonce: [u8; NONCE_LEN],
    salt: [u8; SALT_LEN]
}
impl ServerFirstMsg {
    pub(crate) fn new(cnonce: [u8; NONCE_LEN], snonce: [u8; NONCE_LEN], salt: [u8; SALT_LEN]) -> Self {
        Self { cnonce, snonce, salt }
    }

    #[inline(always)]
    pub fn cnonce(&self) -> [u8; NONCE_LEN] {
        self.cnonce
    }
    #[inline(always)]
    pub fn snonce(&self) -> [u8; NONCE_LEN] {
        self.snonce
    }
    #[inline(always)]
    pub fn salt(&self) -> [u8; SALT_LEN] {
        self.salt
    }
}
impl PacketCore<SERVER_FIRST_LEN> for ServerFirstMsg {
    fn serialize(&self) -> [u8; SERVER_FIRST_LEN] {
        let mut out = [0x00; SERVER_FIRST_LEN];
        out[..NONCE_LEN].copy_from_slice(&self.cnonce);
        out[NONCE_LEN..2*NONCE_LEN].copy_from_slice(&self.snonce);
        out[2*NONCE_LEN..].copy_from_slice(&self.salt);
        out
    }
    fn deserialize(data: [u8; SERVER_FIRST_LEN]) -> Self {
        let cnonce = data[..NONCE_LEN].try_into().unwrap();
        let snonce = data[NONCE_LEN..2*NONCE_LEN].try_into().unwrap();
        let salt = data[2*NONCE_LEN..].try_into().unwrap();

        Self { cnonce, snonce, salt }
    }
}

#[derive(Debug)]
pub struct ClientFinalMsgPartial {
    cnonce: [u8; NONCE_LEN],
    snonce: [u8; NONCE_LEN]
}
impl ClientFinalMsgPartial {
    pub(crate) fn new(cnonce: [u8; NONCE_LEN], snonce: [u8; NONCE_LEN]) -> Self {
        Self { cnonce, snonce }
    }

    pub fn serialize_without_proof(&self) -> [u8; CLIENT_FINISH_LEN-PROOF_LEN] {
        // Implicit proof that length constants match
        let mut out = [0x00; 2*NONCE_LEN];
        out[..NONCE_LEN].copy_from_slice(&self.cnonce);
        out[NONCE_LEN..].copy_from_slice(&self.snonce);
        out
    }
}
#[derive(Debug)]
pub struct ClientFinalMsg {
    cnonce: [u8; NONCE_LEN],
    snonce: [u8; NONCE_LEN],
    proof: [u8; PROOF_LEN]
}

impl ClientFinalMsg {
    pub(crate) fn from_partial(partial: ClientFinalMsgPartial, proof: [u8; PROOF_LEN]) -> Self {
        Self {
            cnonce: partial.cnonce,
            snonce: partial.snonce,
            proof
        }
    }

    #[inline(always)]
    pub fn cnonce(&self) -> [u8; NONCE_LEN] {
        self.cnonce
    }
    #[inline(always)]
    pub fn snonce(&self) -> [u8; NONCE_LEN] {
        self.snonce
    }
    #[inline(always)]
    pub fn proof(&self) -> [u8; PROOF_LEN] {
        self.proof
    }
    pub fn serialize_without_proof(&self) -> [u8; CLIENT_FINISH_LEN-PROOF_LEN] {
        // Implicit proof that length constants match
        let mut out = [0x00; 2*NONCE_LEN];
        out[..NONCE_LEN].copy_from_slice(&self.cnonce);
        out[NONCE_LEN..].copy_from_slice(&self.snonce);
        out
    }
}

impl PacketCore<CLIENT_FINISH_LEN> for ClientFinalMsg {
    fn serialize(&self) -> [u8; CLIENT_FINISH_LEN] {
        let mut out = [0x00; CLIENT_FINISH_LEN];
        out[..NONCE_LEN].copy_from_slice(&self.cnonce);
        out[NONCE_LEN..2*NONCE_LEN].copy_from_slice(&self.snonce);
        out[2*NONCE_LEN..].copy_from_slice(&self.proof);
        out
    }
    fn deserialize(data: [u8; CLIENT_FINISH_LEN]) -> Self {
        let cnonce = data[..NONCE_LEN].try_into().unwrap();
        let snonce = data[NONCE_LEN..2*NONCE_LEN].try_into().unwrap();
        let proof = data[2*NONCE_LEN..].try_into().unwrap();
        Self { cnonce, snonce, proof }
    }
}

// Don't need this for now because final message is just a raw byte array
/*#[derive(Debug)]
pub struct ServerFinalMsg {
    server_sig: [u8; SERVER_FINISH_LEN]
}*/
