//! A controllable clock for tests (FR-17).
#![forbid(unsafe_code)]

use std::sync::Mutex;

use keystone_core::clock::Clock;
use time::{Duration, OffsetDateTime};

/// A clock that returns a set time and moves only when told to.
#[derive(Debug)]
pub struct TestClock {
    now: Mutex<OffsetDateTime>,
}

impl TestClock {
    /// A clock showing `start` (converted to UTC).
    pub fn new(start: OffsetDateTime) -> Self {
        TestClock {
            now: Mutex::new(start.to_offset(time::UtcOffset::UTC)),
        }
    }

    /// A clock showing this build's build date plus `days`.
    pub fn days_after_build(days: i64) -> Self {
        TestClock::new(keystone_core::build_info::build_date() + Duration::days(days))
    }

    /// Sets the time.
    pub fn set(&self, time: OffsetDateTime) {
        *self.lock() = time.to_offset(time::UtcOffset::UTC);
    }

    /// Moves the time forward (or back, with a negative duration).
    pub fn advance(&self, by: Duration) {
        let mut now = self.lock();
        *now += by;
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, OffsetDateTime> {
        self.now
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl Clock for TestClock {
    fn now(&self) -> OffsetDateTime {
        *self.lock()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clock_moves_only_when_told() {
        let clock = TestClock::days_after_build(1);
        let start = clock.now();
        assert_eq!(clock.now(), start);
        clock.advance(Duration::hours(2));
        assert_eq!(clock.now(), start + Duration::hours(2));
        clock.set(start);
        assert_eq!(clock.now(), start);
        assert!(clock.now().offset().is_utc());
    }
}
