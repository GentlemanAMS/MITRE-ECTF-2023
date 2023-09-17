//! This module contains a [`Timer`] implementation that can be used in std environments.
//!
//! See [`StdTimer`] for more information.

use std::time::{Duration, Instant};

pub use ucsc_ectf_util_common::timer::*;

/// A timer that uses [`Instants`](Instant) to implement a [`Timer`] that works in std environments.
pub struct StdTimer {
    duration: Duration,
    end: Instant,
}

impl StdTimer {
    /// Creates a new [`StdTimer`] with a provided [`Duration`]
    /// for when the timer expires.
    pub fn new(duration: Duration) -> Self {
        StdTimer {
            duration,
            end: Instant::now() + duration,
        }
    }
}

impl Timer for StdTimer {
    fn poll(&mut self) -> bool {
        Instant::now() >= self.end
    }

    fn reset(&mut self) {
        self.end = Instant::now() + self.duration;
    }

    fn duration(&self) -> Duration {
        self.duration
    }
}
