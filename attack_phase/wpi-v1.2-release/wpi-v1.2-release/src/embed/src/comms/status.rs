use crate::utils::timing::Timeout;

use super::io::IO;

pub enum StatusError {
	TimedOut,
	FailureCodeReceived(u32)
}

impl StatusError {
	pub fn get_status_code(&self) -> u32 {
		match *self {
			Self::FailureCodeReceived(c) => c,
			Self::TimedOut => 0xDEAD
		}
	}
}

pub enum Status {
	Success,
	Error(u32)
}

pub trait StatusIO: IO {
	fn send_status(&self, code: Status);
	fn check_success<'a, T: Timeout + 'a>(&'a self, timeout: T) -> Result<(), StatusError>;
}

impl<T: IO> StatusIO for T {
	fn send_status(&self, code: Status) {
		let code = match code {
			Status::Success => 0,
			Status::Error(c) => c
		};

		// PANIC JUSTIFICATION:
		// Writing 4 bytes does not require any acknowledgements, which means no errors
		// can occur. Therefore, a panic will never actually happen.
		#[allow(clippy::expect_used)]
		self.write(&code.to_le_bytes()).expect("Infallible operation failed");
	}

	fn check_success<'a, TT: Timeout + 'a>(&'a self, timeout: TT) -> Result<(), StatusError> {
		let mut code = [0u8; 4];
		self.read_with_timeout(&mut code, timeout).map_err(|_| StatusError::TimedOut)?;

		let code = u32::from_le_bytes(code);

		match code {
			0 => Ok(()),
			c => Err(StatusError::FailureCodeReceived(c))
		}
	}
}