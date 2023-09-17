use num_enum::{IntoPrimitive, TryFromPrimitive};

#[derive(TryFromPrimitive, IntoPrimitive)]
#[repr(u8)]
pub enum Error {
    UnalignedFlash,
    InvalidFlashAccess,
    InvalidCmd,
    InvalidRegion,
    InvalidVersion,
    InvalidLen,
    DecryptionFailure,
    EncryptionFailure,
    CapacityOverflow,
    InvalidHash,
    SignatureError,
    EepromWrite,
    EepromRead,
    UartTimeout,
    InvalidCarId,
    InvalidReady,
}

impl From<p256::ecdsa::Error> for Error {
    fn from(_: p256::ecdsa::Error) -> Self {
        Self::SignatureError
    }
}

impl From<chacha20poly1305::aead::Error> for Error {
    fn from(_: chacha20poly1305::aead::Error) -> Self {
        Self::DecryptionFailure
    }
}

pub type Result<T> = core::result::Result<T, Error>;
