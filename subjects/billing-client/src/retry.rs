use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::error::Error;

/// Exponential backoff with full jitter.
///
/// Defaults mirror the provider's published guidance: five attempts over
/// roughly eight seconds, which stays inside a typical 30s request budget.
#[derive(Debug, Clone)]
pub struct RetryPolicy {
    pub max_attempts: u32,
    pub initial_backoff: Duration,
    pub max_backoff: Duration,
    pub multiplier: f64,
    /// When false, sleeps are deterministic. Tests set this.
    pub jitter: bool,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        RetryPolicy {
            max_attempts: 5,
            initial_backoff: Duration::from_millis(250),
            max_backoff: Duration::from_secs(4),
            multiplier: 2.0,
            jitter: true,
        }
    }
}

impl RetryPolicy {
    /// Disable retries entirely. Useful for operations the caller wants to
    /// sequence itself, and for tests that assert on exactly one call.
    pub fn none() -> Self {
        RetryPolicy { max_attempts: 1, ..Default::default() }
    }

    /// Backoff before the given attempt, honouring any server-supplied hint.
    fn delay_for(&self, attempt: u32, hint: Option<Duration>) -> Duration {
        if let Some(hint) = hint {
            return hint.min(self.max_backoff);
        }
        let exponent = attempt.saturating_sub(1) as i32;
        let scaled = self.initial_backoff.as_secs_f64() * self.multiplier.powi(exponent);
        let capped = scaled.min(self.max_backoff.as_secs_f64());
        let chosen = if self.jitter { capped * jitter_fraction() } else { capped };
        Duration::from_secs_f64(chosen.max(0.0))
    }
}

/// xorshift64* seeded once from the wall clock. Avoids pulling in `rand` for
/// what is only ever used to de-synchronise retries across a fleet.
fn jitter_fraction() -> f64 {
    static STATE: AtomicU64 = AtomicU64::new(0);

    let mut x = STATE.load(Ordering::Relaxed);
    if x == 0 {
        x = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0x2545_F491_4F6C_DD1D)
            | 1;
    }
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    STATE.store(x, Ordering::Relaxed);

    let bits = x.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 11;
    bits as f64 / (1u64 << 53) as f64
}

/// Run `operation` until it succeeds, exhausts the policy, or fails with
/// something not worth retrying.
///
/// The closure receives the 1-based attempt number so callers can log it or
/// vary a header. Sleeping happens on the calling thread, which is what a
/// blocking client is for.
pub fn with_retry<T, F>(policy: &RetryPolicy, mut operation: F) -> Result<T, Error>
where
    F: FnMut(u32) -> Result<T, Error>,
{
    let mut attempt = 1;
    loop {
        match operation(attempt) {
            Ok(value) => return Ok(value),
            Err(err) => {
                if attempt >= policy.max_attempts || !err.is_retryable() {
                    return Err(finalize(attempt, err, policy.max_attempts));
                }
                let hint = match &err {
                    Error::RateLimited { retry_after, .. } => Some(*retry_after),
                    _ => None,
                };
                thread::sleep(policy.delay_for(attempt, hint));
                attempt += 1;
            }
        }
    }
}

/// Same contract, but the caller supplies a sleeper. Lets tests drive the retry
/// loop without spending wall-clock time.
pub fn with_retry_using<T, F, S>(policy: &RetryPolicy, mut operation: F, mut sleeper: S) -> Result<T, Error>
where
    F: FnMut(u32) -> Result<T, Error>,
    S: FnMut(Duration),
{
    let mut attempt = 1;
    loop {
        match operation(attempt) {
            Ok(value) => return Ok(value),
            Err(err) => {
                if attempt >= policy.max_attempts || !err.is_retryable() {
                    return Err(finalize(attempt, err, policy.max_attempts));
                }
                let hint = match &err {
                    Error::RateLimited { retry_after, .. } => Some(*retry_after),
                    _ => None,
                };
                sleeper(policy.delay_for(attempt, hint));
                attempt += 1;
            }
        }
    }
}

fn finalize(attempt: u32, err: Error, max_attempts: u32) -> Error {
    if attempt >= max_attempts && max_attempts > 1 && err.is_retryable() {
        Error::RetriesExhausted { attempts: attempt, last: Box::new(err) }
    } else {
        err
    }
}
