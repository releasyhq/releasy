use std::time::{SystemTime, SystemTimeError, UNIX_EPOCH};

pub fn now_ts() -> Result<i64, SystemTimeError> {
    now_ts_from(SystemTime::now())
}

fn now_ts_from(time: SystemTime) -> Result<i64, SystemTimeError> {
    time.duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn now_ts_from_epoch_is_zero() {
        let ts = now_ts_from(UNIX_EPOCH).expect("timestamp");
        assert_eq!(ts, 0);
    }

    #[test]
    fn now_ts_from_before_epoch_errors() {
        let past = UNIX_EPOCH - Duration::from_secs(5);
        let err = now_ts_from(past).expect_err("expected error");
        assert!(err.duration().as_secs() >= 5);
    }
}
