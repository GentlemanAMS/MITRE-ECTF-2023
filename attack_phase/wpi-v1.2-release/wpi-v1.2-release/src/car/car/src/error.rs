use ectf::comms::{self, io, status::StatusError};

/// Errors that can occur during the unlock process.
pub enum UnlockError {
	/// Occurs when an incorrect unlock password is provided.
	IncorrectPassword,
	/// Occurs when an incorrect car ID is provided.
	IncorrectCarID,
}

impl UnlockError {
	pub fn get_status_code(&self) -> u32 {
		match *self {
			Self::IncorrectPassword => 0x5000,
			Self::IncorrectCarID => 0x5002,
		}
	}
}

/// Errors that can occur during the start process.
pub enum StartError {
	/// Occurs when an incorrect car ID is provided.
	IncorrectCarID,
}

impl StartError {
	pub fn get_status_code(&self) -> u32 {
		match *self {
			Self::IncorrectCarID => 0x6000
		}
	}
}

/// Errors that can occur in the car firmware.
pub enum Error {
	/// Occurs when a communication operation fails.
	CommunicationFailure(comms::error::Error),

    /// Occurs when a cryptographic operation fails.
    CryptoFailure(chacha20poly1305::Error),

	/// Occurs when a signature-related operation fails.
	SignatureFailure(ed25519_dalek::SignatureError),

	/// Occurs when a non-success status is received.
	BadStatus(StatusError),

	/// Occurs when unlocking the car fails.
	UnlockFailure(UnlockError),

	/// Occurs when starting the car fails.
	StartFailure(StartError),

    /// Occurs when an I/O operation fails.
    IOFailure(io::Error)
}

impl Error {
	pub fn get_status_code(&self) -> u32 {
		match self {
			Self::CommunicationFailure(ce) => ce.get_status_code(),
			Self::SignatureFailure(_) => 0x1003,
			Self::CryptoFailure(_) => 0x1004,
			Self::BadStatus(se) => se.get_status_code(),
			Self::UnlockFailure(ue) => ue.get_status_code(),
			Self::StartFailure(se) => se.get_status_code(),
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

impl From<StatusError> for Error {
	fn from(value: StatusError) -> Self {
		Self::BadStatus(value)
	}
}

impl From<UnlockError> for Error {
	fn from(value: UnlockError) -> Self {
		Self::UnlockFailure(value)
	}
}

impl From<StartError> for Error {
	fn from(value: StartError) -> Self {
		Self::StartFailure(value)
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