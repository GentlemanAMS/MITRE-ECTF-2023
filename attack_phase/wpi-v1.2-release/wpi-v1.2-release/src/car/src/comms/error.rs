use super::io;

/// Errors that can occur in the communication layer.
#[derive(Debug)]
pub enum Error {
    /// Occurs when a packet is determined to have an invalid nonce.
    InvalidNonce,

    /// Occurs when a PIN cannot be parsed.
    PinError,

    /// Occurs when an invalid message type is included in a packet.
    InvalidMessageIDError,

	/// Occurs when a signature check fails.
	InvalidSignature(ed25519_dalek::SignatureError),

    /// Occurs when a cryptographic operation fails.
    CryptoError(chacha20poly1305::Error),

	MalformedMessageError,

    /// Occurs when an I/O operation fails.
    IOError(io::Error)
}

impl Error {
	pub fn get_status_code(&self) -> u32 {
        match self {
            Self::InvalidNonce => 0x1000,
            Self::PinError => 0x1001,
            Self::InvalidMessageIDError => 0x1002,
            Self::InvalidSignature(_) => 0x1003,
            Self::CryptoError(_) => 0x1004,
            Self::MalformedMessageError => 0x1005,
            Self::IOError(e) => e.get_status_code()
        }
    }
}

impl From<ed25519_dalek::SignatureError> for Error {
	fn from(value: ed25519_dalek::SignatureError) -> Self {
		Self::InvalidSignature(value)
	}
}

impl From<chacha20poly1305::Error> for Error {
	fn from(value: chacha20poly1305::Error) -> Self {
		Self::CryptoError(value)
	}
}

impl From<io::Error> for Error {
    fn from(value: io::Error) -> Self {
        Self::IOError(value)
    }
}