use serde::Deserialize;
use std::fmt;
use std::time::Duration;

/// Everything that can go wrong on the way to a typed response.
#[derive(Debug)]
pub enum Error {
    /// The request never produced an HTTP response.
    Transport(TransportError),

    /// The API answered with a structured error envelope.
    Api(ApiError),

    /// The API answered 429. `retry_after` comes from the header when present.
    RateLimited { retry_after: Duration, request_id: Option<String> },

    /// Status was 2xx but the body did not match the expected shape. Almost
    /// always means the caller is on an older SDK than the API.
    Decode { path: String, status: u16, source: serde_json::Error },

    /// Request body could not be serialised. A bug on our side.
    Encode(serde_json::Error),

    /// Retry budget exhausted. Carries the last failure seen.
    RetriesExhausted { attempts: u32, last: Box<Error> },
}

impl Error {
    /// Whether re-issuing the identical request could plausibly succeed.
    ///
    /// Note that 409 is deliberately *not* retryable: our idempotency keys mean
    /// a conflict indicates a genuine concurrent mutation, not a lost response.
    pub fn is_retryable(&self) -> bool {
        match self {
            Error::Transport(e) => e.is_retryable(),
            Error::RateLimited { .. } => true,
            Error::Api(api) => matches!(api.status, 500 | 502 | 503 | 504),
            Error::Decode { .. } | Error::Encode(_) | Error::RetriesExhausted { .. } => false,
        }
    }

    /// Correlation id to quote when opening a support ticket.
    pub fn request_id(&self) -> Option<&str> {
        match self {
            Error::Api(api) => api.request_id.as_deref(),
            Error::RateLimited { request_id, .. } => request_id.as_deref(),
            Error::RetriesExhausted { last, .. } => last.request_id(),
            _ => None,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Transport(e) => write!(f, "transport failure: {}", e),
            Error::Api(e) => write!(f, "{}", e),
            Error::RateLimited { retry_after, .. } => {
                write!(f, "rate limited, retry after {:?}", retry_after)
            }
            Error::Decode { path, status, source } => write!(
                f,
                "could not decode {} response from {}: {}",
                status, path, source
            ),
            Error::Encode(e) => write!(f, "could not encode request body: {}", e),
            Error::RetriesExhausted { attempts, last } => {
                write!(f, "gave up after {} attempts, last error: {}", attempts, last)
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Transport(e) => Some(e),
            Error::Decode { source, .. } | Error::Encode(source) => Some(source),
            Error::RetriesExhausted { last, .. } => Some(&**last),
            _ => None,
        }
    }
}

impl From<TransportError> for Error {
    fn from(e: TransportError) -> Self {
        Error::Transport(e)
    }
}

/// The provider's error envelope: `{"error": {"type": ..., "code": ...}}`.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiError {
    #[serde(rename = "type", default)]
    pub kind: ApiErrorKind,
    #[serde(default)]
    pub code: String,
    #[serde(default)]
    pub message: String,
    /// Which field the API objected to, for validation failures.
    #[serde(default)]
    pub param: Option<String>,
    #[serde(default)]
    pub doc_url: Option<String>,
    #[serde(skip)]
    pub status: u16,
    #[serde(skip)]
    pub request_id: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApiErrorKind {
    /// The caller sent something invalid.
    InvalidRequest,
    /// Credentials missing, expired, or scoped too narrowly.
    Authentication,
    /// The card or bank rejected the operation.
    CardDeclined,
    /// A downstream processor was unavailable.
    Processing,
    #[default]
    Unknown,
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.status, self.message)?;
        if !self.code.is_empty() {
            write!(f, " (code={})", self.code)?;
        }
        if let Some(param) = &self.param {
            write!(f, " (param={})", param)?;
        }
        if let Some(id) = &self.request_id {
            write!(f, " (request_id={})", id)?;
        }
        Ok(())
    }
}

impl std::error::Error for ApiError {}

/// Failures below HTTP: DNS, connect, TLS, socket, read timeout.
#[derive(Debug)]
pub enum TransportError {
    Connect(String),
    Tls(String),
    Timeout { elapsed: Duration },
    Io(std::io::Error),
    /// Server closed the connection mid-response.
    IncompleteResponse,
}

impl TransportError {
    pub fn is_retryable(&self) -> bool {
        // A timeout on a non-idempotent POST is still safe to retry because the
        // client always attaches an idempotency key.
        !matches!(self, TransportError::Tls(_))
    }
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransportError::Connect(host) => write!(f, "could not connect to {}", host),
            TransportError::Tls(detail) => write!(f, "tls handshake failed: {}", detail),
            TransportError::Timeout { elapsed } => write!(f, "timed out after {:?}", elapsed),
            TransportError::Io(e) => write!(f, "socket error: {}", e),
            TransportError::IncompleteResponse => write!(f, "connection closed mid-response"),
        }
    }
}

impl std::error::Error for TransportError {}

impl From<std::io::Error> for TransportError {
    fn from(e: std::io::Error) -> Self {
        TransportError::Io(e)
    }
}
