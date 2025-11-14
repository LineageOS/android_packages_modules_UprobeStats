//! UprobeStats library
mod art;
pub mod bpf_map;
pub mod config_resolver;
pub mod guardrail;
mod process;

use std::time::{Duration, Instant};

const BPF_DIR: &str = "/sys/fs/bpf/uprobestats/";
pub(crate) fn prefix_bpf(path: &str) -> String {
    BPF_DIR.to_string() + path
}

/// Basic timer implementation
pub struct Timer {
    now: Instant,
    duration: Duration,
}

impl Timer {
    /// Construct a timer for the given duration.
    pub fn new(duration: Duration) -> Self {
        let now = Instant::now();
        Self { now, duration }
    }

    /// Check the time remaining. `None` if expired, else `Some(remaining)`.
    pub fn remaining_millis(&self) -> Option<u128> {
        self.duration.as_millis().checked_sub(self.now.elapsed().as_millis())
    }
}
