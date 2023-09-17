use ectf::comms::{self, io, status::StatusError};

/// Errors that can occur while enabling a feature.
pub enum FeatureEnableError {
	/// Occurs when all feature slots are occupied and no new
	/// features can be enabled.
	NoSlotAvailable,

	/// Occurs when an attempt is made to enable a feature that 
	/// is packaged for another car.
	InvalidCarID,

	/// Occurs when a feature is already enabled.
	AlreadyEnabled,

	/// Occurs when the signature for a feature cannot be verified.
	InvalidSignature,
}

impl FeatureEnableError {
	pub fn get_status_code(&self) -> u32 {
		match *self {
			Self::NoSlotAvailable => 0x3000,
			Self::InvalidCarID => 0x3001,
			Self::AlreadyEnabled => 0x3002,
			Self::InvalidSignature => 0x3003
		}
	}
}

/// Errors that can occur during the pairing process.
pub enum PairingError {
	/// Occurs when a PIN is supplied that does not conform to
	/// the required format (6 hexadecimal digits.)
	MalformedPIN,

	/// Occurs when an incorrect PIN is supplied.
	IncorrectPIN,

	/// Occurs when a pairing request is sent to an unpaired fob 
	/// by another unpaired fob.
	FobNotPaired,

	/// Occurs when a pairing request is sent to a paired fob
	/// by a client.
	FobAlreadyPaired
}

impl PairingError {
	pub fn get_status_code(&self) -> u32 {
		match *self {
			Self::MalformedPIN => 0x4000,
			Self::IncorrectPIN => 0x4001,
			Self::FobNotPaired => 0x4002,
			Self::FobAlreadyPaired => 0x4003,
		}
	}
}

/// Errors that can occur in the fob firmware.
pub enum Error {
	/// Occurs when a communication operation fails.
	CommunicationFailure(comms::error::Error),

    /// Occurs when a cryptographic operation fails.
    CryptoFailure(chacha20poly1305::Error),

	/// Occurs when a signature-related operation fails.
	SignatureFailure(ed25519_dalek::SignatureError),

	/// Occurs when a feature cannot be enabled.
	FeatureEnableFailure(FeatureEnableError),

	/// Occurs when pairing fails.
	PairFailure(PairingError),

	/// Occurs when a non-success status is received.
	BadStatus(StatusError),

    /// Occurs when an I/O operation fails.
    IOFailure(io::Error)
}

impl Error {
	pub fn get_status_code(&self) -> u32 {
		match self {
			Self::CommunicationFailure(ce) => ce.get_status_code(),
			Self::SignatureFailure(_) => 0x1003,
			Self::CryptoFailure(_) => 0x1004,
			Self::FeatureEnableFailure(fe) => fe.get_status_code(),
			Self::PairFailure(pe) => pe.get_status_code(),
			Self::BadStatus(se) => se.get_status_code(),
			Self::IOFailure(ie) => ie.get_status_code(),
		}
	}
}

impl From<comms::error::Error> for Error {
	fn from(value: comms::error::Error) -> Self {
		Self::CommunicationFailure(value)
	}
}

impl From<chacha20poly1305::Error> for Error {
	fn from(value: chacha20poly1305::Error) -> Self {
		Self::CryptoFailure(value)
	}
}

impl From<FeatureEnableError> for Error {
	fn from(value: FeatureEnableError) -> Self {
		Self::FeatureEnableFailure(value)
	}
}

impl From<PairingError> for Error {
	fn from(value: PairingError) -> Self {
		Self::PairFailure(value)
	}
}

impl From<StatusError> for Error {
	fn from(value: StatusError) -> Self {
		Self::BadStatus(value)
	}
}

impl From<ed25519_dalek::SignatureError> for Error {
	fn from(value: ed25519_dalek::SignatureError) -> Self {
		Self::SignatureFailure(value)
	}
}

impl From<io::Error> for Error {
    fn from(value: io::Error) -> Self {
        Self::IOFailure(value)
    }
}