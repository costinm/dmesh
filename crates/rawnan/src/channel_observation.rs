//! Bounded, adapter-neutral channel-observation counters.
//!
//! This is deliberately a receive-observation estimate, not PHY CCA airtime:
//! a monitor only sees frames delivered by its driver. Host and ESP adapters
//! feed a monotonic receive timestamp plus frame length and expose the same
//! frame/byte and inter-arrival metrics to their control handlers.

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ChannelObservation {
    frames: u64,
    bytes: u64,
    first_us: Option<u64>,
    last_us: Option<u64>,
    interval_count: u64,
    interval_total_us: u64,
    interval_min_us: u64,
    interval_max_us: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ChannelObservationSummary {
    pub frames: u64,
    pub bytes: u64,
    pub elapsed_us: u64,
    pub interval_count: u64,
    pub interval_total_us: u64,
    pub interval_min_us: u64,
    pub interval_max_us: u64,
}

impl ChannelObservation {
    /// Record one received frame. Timestamps must use one monotonic domain;
    /// an out-of-order sample still counts as a frame but contributes no
    /// interval, avoiding an underflow that would corrupt the mean.
    pub fn observe(&mut self, received_us: u64, bytes: usize) {
        self.frames = self.frames.saturating_add(1);
        self.bytes = self.bytes.saturating_add(bytes as u64);
        if self.first_us.is_none() {
            self.first_us = Some(received_us);
        }
        if let Some(previous_us) = self.last_us {
            if received_us >= previous_us {
                let interval_us = received_us - previous_us;
                self.interval_count = self.interval_count.saturating_add(1);
                self.interval_total_us = self.interval_total_us.saturating_add(interval_us);
                if self.interval_count == 1 || interval_us < self.interval_min_us {
                    self.interval_min_us = interval_us;
                }
                if interval_us > self.interval_max_us {
                    self.interval_max_us = interval_us;
                }
            }
        }
        self.last_us = Some(received_us);
    }

    pub fn summary(&self) -> ChannelObservationSummary {
        ChannelObservationSummary {
            frames: self.frames,
            bytes: self.bytes,
            elapsed_us: self
                .first_us
                .zip(self.last_us)
                .map(|(first, last)| last.saturating_sub(first))
                .unwrap_or(0),
            interval_count: self.interval_count,
            interval_total_us: self.interval_total_us,
            interval_min_us: self.interval_min_us,
            interval_max_us: self.interval_max_us,
        }
    }
}

impl ChannelObservationSummary {
    pub fn interval_mean_us(&self) -> u64 {
        if self.interval_count == 0 {
            0
        } else {
            self.interval_total_us / self.interval_count
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_bytes_elapsed_and_interarrival_bounds() {
        let mut observation = ChannelObservation::default();
        observation.observe(100, 10);
        observation.observe(125, 20);
        observation.observe(200, 30);
        let summary = observation.summary();
        assert_eq!(summary.frames, 3);
        assert_eq!(summary.bytes, 60);
        assert_eq!(summary.elapsed_us, 100);
        assert_eq!(summary.interval_count, 2);
        assert_eq!(summary.interval_min_us, 25);
        assert_eq!(summary.interval_max_us, 75);
        assert_eq!(summary.interval_mean_us(), 50);
    }

    #[test]
    fn out_of_order_sample_does_not_underflow_an_interval() {
        let mut observation = ChannelObservation::default();
        observation.observe(100, 1);
        observation.observe(80, 1);
        assert_eq!(observation.summary().interval_count, 0);
    }
}
