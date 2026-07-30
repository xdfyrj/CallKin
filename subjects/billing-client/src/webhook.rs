use hmac::{Hmac, Mac};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::Value;
use sha2::Sha256;
use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

/// Reject deliveries whose timestamp is further than this from our clock, so a
/// captured payload cannot be replayed indefinitely.
const DEFAULT_TOLERANCE: Duration = Duration::from_secs(300);

#[derive(Debug)]
pub enum WebhookError {
    /// `Billing-Signature` was absent or unparseable.
    MalformedSignature,
    /// No candidate signature matched any configured secret.
    NoMatch,
    /// Timestamp outside the tolerance window.
    TooOld { age: Duration, tolerance: Duration },
    /// Signature was valid but the body was not the expected event shape.
    MalformedPayload(serde_json::Error),
    /// The event's `data.object` did not decode into the requested type.
    UnexpectedObject { event_type: String, source: serde_json::Error },
}

impl fmt::Display for WebhookError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WebhookError::MalformedSignature => write!(f, "signature header missing or malformed"),
            WebhookError::NoMatch => write!(f, "no configured secret produced a matching signature"),
            WebhookError::TooOld { age, tolerance } => {
                write!(f, "delivery is {:?} old, tolerance is {:?}", age, tolerance)
            }
            WebhookError::MalformedPayload(e) => write!(f, "event body is not valid: {}", e),
            WebhookError::UnexpectedObject { event_type, source } => {
                write!(f, "could not decode object of '{}' event: {}", event_type, source)
            }
        }
    }
}

impl std::error::Error for WebhookError {}

/// A verified webhook delivery.
#[derive(Debug, Clone, Deserialize)]
pub struct Event {
    pub id: String,
    #[serde(rename = "type")]
    pub event_type: String,
    pub created: i64,
    #[serde(default)]
    pub api_version: Option<String>,
    #[serde(default)]
    pub livemode: bool,
    pub data: EventData,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EventData {
    /// The resource the event is about, in whatever shape the API version sent.
    pub object: Value,
    /// For `*.updated` events: the fields as they were before.
    #[serde(default)]
    pub previous_attributes: Option<Value>,
}

impl Event {
    /// Decode `data.object` into the resource type this event carries.
    ///
    /// The handler decides what to expect based on `event_type`; a mismatch is
    /// an error rather than a panic, because the provider can add fields or
    /// change shapes across API versions.
    pub fn object<T: DeserializeOwned>(&self) -> Result<T, WebhookError> {
        serde_json::from_value(self.data.object.clone()).map_err(|source| {
            WebhookError::UnexpectedObject { event_type: self.event_type.clone(), source }
        })
    }

    /// Reconstruct the pre-update state by overlaying `previous_attributes`
    /// onto the current object. Returns `None` for events that carry no diff.
    pub fn previous<T: DeserializeOwned>(&self) -> Result<Option<T>, WebhookError> {
        let Some(previous) = &self.data.previous_attributes else {
            return Ok(None);
        };
        let mut restored = self.data.object.clone();
        overlay(&mut restored, previous);
        let value = serde_json::from_value(restored).map_err(|source| {
            WebhookError::UnexpectedObject { event_type: self.event_type.clone(), source }
        })?;
        Ok(Some(value))
    }

    /// True for events whose `type` starts with the given prefix, e.g.
    /// `event.is("invoice.")`.
    pub fn is(&self, prefix: &str) -> bool {
        self.event_type.starts_with(prefix)
    }
}

fn overlay(target: &mut Value, patch: &Value) {
    match (target, patch) {
        (Value::Object(target_map), Value::Object(patch_map)) => {
            for (key, patch_child) in patch_map {
                match target_map.get_mut(key) {
                    Some(target_child) => overlay(target_child, patch_child),
                    None => {
                        target_map.insert(key.clone(), patch_child.clone());
                    }
                }
            }
        }
        (slot, other) => *slot = other.clone(),
    }
}

/// Verifies `Billing-Signature` headers of the form `t=<unix>,v1=<hex>`.
///
/// Holds more than one secret so that a rotation can overlap: add the new
/// secret, flip it at the provider, then drop the old one on the next deploy.
pub struct WebhookVerifier {
    secrets: Vec<String>,
    tolerance: Duration,
}

impl WebhookVerifier {
    pub fn new(secret: impl Into<String>) -> Self {
        WebhookVerifier { secrets: vec![secret.into()], tolerance: DEFAULT_TOLERANCE }
    }

    pub fn with_secret(mut self, secret: impl Into<String>) -> Self {
        self.secrets.push(secret.into());
        self
    }

    pub fn tolerance(mut self, tolerance: Duration) -> Self {
        self.tolerance = tolerance;
        self
    }

    /// Verify against the system clock.
    pub fn verify(&self, payload: &[u8], signature_header: &str) -> Result<Event, WebhookError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        self.verify_at(payload, signature_header, now)
    }

    /// Verify against a caller-supplied clock. Tests use this; so does any
    /// replay tool that needs to re-process an archived delivery.
    pub fn verify_at(
        &self,
        payload: &[u8],
        signature_header: &str,
        now: i64,
    ) -> Result<Event, WebhookError> {
        let header = SignatureHeader::parse(signature_header)?;

        let age = now.saturating_sub(header.timestamp);
        if age.unsigned_abs() > self.tolerance.as_secs() {
            return Err(WebhookError::TooOld {
                age: Duration::from_secs(age.unsigned_abs()),
                tolerance: self.tolerance,
            });
        }

        let mut signed = Vec::with_capacity(payload.len() + 24);
        signed.extend_from_slice(header.timestamp.to_string().as_bytes());
        signed.push(b'.');
        signed.extend_from_slice(payload);

        let matched = self.secrets.iter().any(|secret| {
            let expected = sign(secret.as_bytes(), &signed);
            header
                .candidates
                .iter()
                .any(|candidate| constant_time_eq(candidate.as_bytes(), expected.as_bytes()))
        });

        if !matched {
            return Err(WebhookError::NoMatch);
        }

        serde_json::from_slice::<Event>(payload).map_err(WebhookError::MalformedPayload)
    }
}

struct SignatureHeader {
    timestamp: i64,
    candidates: Vec<String>,
}

impl SignatureHeader {
    fn parse(raw: &str) -> Result<Self, WebhookError> {
        let mut timestamp = None;
        let mut candidates = Vec::new();

        for part in raw.split(',') {
            let Some((key, value)) = part.trim().split_once('=') else {
                continue;
            };
            match key {
                "t" => timestamp = value.parse::<i64>().ok(),
                // v0 is the deprecated scheme; ignore it rather than accept it.
                "v1" => candidates.push(value.to_ascii_lowercase()),
                _ => {}
            }
        }

        match timestamp {
            Some(timestamp) if !candidates.is_empty() => Ok(SignatureHeader { timestamp, candidates }),
            _ => Err(WebhookError::MalformedSignature),
        }
    }
}

/// HMAC-SHA256 of `message` under `key`, lowercase hex.
pub fn sign(key: &[u8], message: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("hmac accepts keys of any length");
    mac.update(message);
    let digest = mac.finalize().into_bytes();

    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        hex.push(nibble(byte >> 4));
        hex.push(nibble(byte & 0x0f));
    }
    hex
}

/// Build the header a sender would produce. Exposed so integration tests and
/// local replay tooling can forge deliveries against a test secret.
pub fn sign_payload(secret: &str, payload: &[u8], timestamp: i64) -> String {
    let mut signed = Vec::with_capacity(payload.len() + 24);
    signed.extend_from_slice(timestamp.to_string().as_bytes());
    signed.push(b'.');
    signed.extend_from_slice(payload);
    format!("t={},v1={}", timestamp, sign(secret.as_bytes(), &signed))
}

fn nibble(value: u8) -> char {
    match value {
        0..=9 => (b'0' + value) as char,
        _ => (b'a' + value - 10) as char,
    }
}

/// Compares without leaking a match prefix through timing.
fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in left.iter().zip(right.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}
