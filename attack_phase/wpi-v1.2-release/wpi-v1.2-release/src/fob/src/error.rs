/// Errors that can occur in the PARED core.
#[derive(Debug)]
pub enum PAREDError {
    /// Occurs when a packet is determined to have an invalid nonce.
    InvalidNonce,

    /// Occurs when a cryptographic operation fails.
    CryptoError,

    /// Occurs when a PIN cannot be parsed.
    PinError,

    /// Occurs when an invalid message type is included in a packet.
    InvalidMessageIDError,

    /// Occurs when a message cannot be parsed.
    MalformedMessageError,
    
    /// Occurs when an attempt to read data times out.
    TimeoutError
}
