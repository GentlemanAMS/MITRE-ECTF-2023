//! Utilities for generating delays and managing timeouts.

/// A timeout driven by a time source.
pub trait Timeout {
	/// Returns `true` if the timeout has expired.
	fn has_expired(&self) -> bool;
}

/// A time tracker that is driven by a time source.
pub trait TimeKeeper<'a> {
	type Timeout: Timeout;

	/// Generates a delay of `delay_length_ms` milliseconds.
	fn delay(&'a mut self, delay_length_ms: u32) {
		let timeout = self.create_timeout(delay_length_ms);

		loop {
			if timeout.has_expired() {
				break;
			}
		}
	}

	/// Generates a [`Timeout`] that expires after `length_ms` milliseconds.
	fn create_timeout(&'a self, length_ms: u32) -> Self::Timeout;
}

#[cfg(target_arch = "arm")]
mod hw {
    use core::num::Wrapping;

    use cortex_m::peripheral::SYST;
    use cortex_m_systick_countdown::{PollingSysTick, CountsMillis, SysTickCalibration};

	/// A SysTick-based timeout.
	pub struct HardwareTimeout<'a> {
		poller: &'a PollingSysTick,
		expires_at: Wrapping<u32>
	}

	impl<'a> HardwareTimeout<'a> {
		/// Creates a [`HardwareTimeout`] lasting `duration` milliseconds.
		pub fn new(poller: &'a PollingSysTick, duration: u32) -> Self {
			let now = poller.count();
			let expires_at = now + Wrapping(duration);

			Self {
				poller,
				expires_at
			}
		}
	}

	impl<'a> super::Timeout for HardwareTimeout<'a> {
		fn has_expired(&self) -> bool {
			self.poller.count() >= self.expires_at
		}
	}

	/// A SysTick-based time keeper.
	pub struct HardwareTimeKeeper {
		poller: PollingSysTick,
	}

	impl HardwareTimeKeeper {
		/// Creates a [`HardwareTimeKeeper`], consuming the program's [`SYST`] resource.
		pub fn new(syst: SYST) -> Self {
			Self {
				poller: PollingSysTick::new(
					syst, 
					&SysTickCalibration::from_clock_hz(80_000_000)),
			}
		}
	}

	impl<'a> super::TimeKeeper<'a> for HardwareTimeKeeper {
		type Timeout = HardwareTimeout<'a>;

		fn create_timeout(&'a self, length_ms: u32) -> Self::Timeout {
			Self::Timeout::new(&self.poller, length_ms)
		}
	}
}

#[cfg(test)]
mod test {
    use core::{time::Duration, ops::Add};
    use std::time::Instant;

    use super::Timeout;

	pub struct TestTimeKeeper;

	pub struct TestTimeout {
		expires_at: Instant
	}

	impl Timeout for TestTimeout {
		fn has_expired(&self) -> bool {
			Instant::now() >= self.expires_at
		}
	}

	impl TestTimeKeeper {
		pub fn new() -> Self {
			Self
		}
	}

	impl<'a> super::TimeKeeper<'a> for TestTimeKeeper {
		type Timeout = TestTimeout;

		fn create_timeout(&'a self, length_ms: u32) -> Self::Timeout {
			Self::Timeout {
				expires_at: Instant::now().add(Duration::from_millis(length_ms as u64))
			}
		}
	}
}

#[cfg(target_arch = "arm")]
pub use hw::HardwareTimeKeeper;
#[cfg(test)]
pub use test::TestTimeKeeper;