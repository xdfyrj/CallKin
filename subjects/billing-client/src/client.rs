use serde::de::DeserializeOwned;
use serde::Serialize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::error::{ApiError, Error};
use crate::http::{Method, Request, Response, Transport};
use crate::page::{Cursored, ListParams, Page, Paginator};
use crate::retry::{with_retry, RetryPolicy};

/// API version this SDK is written against. Sent on every request so the
/// provider does not silently move us onto a newer schema.
pub const API_VERSION: &str = "2024-11-20";

const DEFAULT_BASE_URL: &str = "https://api.billing.example.com";
const USER_AGENT: &str = concat!("billing-client-rs/", env!("CARGO_PKG_VERSION"));

pub struct ClientBuilder {
    api_key: String,
    base_url: String,
    transport: Option<Arc<dyn Transport>>,
    retry: RetryPolicy,
    timeout: Duration,
    account: Option<String>,
}

impl ClientBuilder {
    pub fn new(api_key: impl Into<String>) -> Self {
        ClientBuilder {
            api_key: api_key.into(),
            base_url: DEFAULT_BASE_URL.to_string(),
            transport: None,
            retry: RetryPolicy::default(),
            timeout: Duration::from_secs(30),
            account: None,
        }
    }

    pub fn base_url(mut self, url: impl Into<String>) -> Self {
        self.base_url = url.into().trim_end_matches('/').to_string();
        self
    }

    pub fn transport(mut self, transport: Arc<dyn Transport>) -> Self {
        self.transport = Some(transport);
        self
    }

    pub fn retry(mut self, policy: RetryPolicy) -> Self {
        self.retry = policy;
        self
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Act on behalf of a connected account (platform integrations).
    pub fn on_behalf_of(mut self, account_id: impl Into<String>) -> Self {
        self.account = Some(account_id.into());
        self
    }

    pub fn build(self) -> Client {
        let transport = self
            .transport
            .expect("a Transport must be supplied; see billing_client::http::Transport");
        Client {
            transport,
            api_key: self.api_key,
            base_url: self.base_url,
            retry: self.retry,
            timeout: self.timeout,
            account: self.account,
        }
    }
}

/// Blocking handle on the Billing API. Cheap to clone by wrapping in `Arc`;
/// safe to share across threads.
pub struct Client {
    transport: Arc<dyn Transport>,
    api_key: String,
    base_url: String,
    retry: RetryPolicy,
    timeout: Duration,
    account: Option<String>,
}

impl Client {
    pub fn builder(api_key: impl Into<String>) -> ClientBuilder {
        ClientBuilder::new(api_key)
    }

    // ---- typed verbs -----------------------------------------------------

    /// GET a single resource.
    pub fn get<R: DeserializeOwned>(&self, path: &str) -> Result<R, Error> {
        self.send::<(), R>(Method::Get, path, &[], None, None)
    }

    /// GET with query parameters.
    pub fn get_with<R: DeserializeOwned>(
        &self,
        path: &str,
        query: &[(String, String)],
    ) -> Result<R, Error> {
        self.send::<(), R>(Method::Get, path, query, None, None)
    }

    /// POST a body, attaching a generated idempotency key so that a retried
    /// request cannot double-charge anyone.
    pub fn post<B: Serialize, R: DeserializeOwned>(&self, path: &str, body: &B) -> Result<R, Error> {
        let key = new_idempotency_key();
        self.send::<B, R>(Method::Post, path, &[], Some(body), Some(&key))
    }

    /// POST under a caller-supplied idempotency key. Use this when the key must
    /// survive process restarts — derive it from your own primary key.
    pub fn post_idempotent<B: Serialize, R: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
        idempotency_key: &str,
    ) -> Result<R, Error> {
        self.send::<B, R>(Method::Post, path, &[], Some(body), Some(idempotency_key))
    }

    pub fn delete<R: DeserializeOwned>(&self, path: &str) -> Result<R, Error> {
        self.send::<(), R>(Method::Delete, path, &[], None, None)
    }

    // ---- pagination ------------------------------------------------------

    /// Fetch exactly one page.
    pub fn list_page<R: DeserializeOwned>(
        &self,
        path: &str,
        params: &ListParams,
    ) -> Result<Page<R>, Error> {
        self.get_with::<Page<R>>(path, &params.to_query())
    }

    /// Lazily iterate a whole collection.
    pub fn list<R>(&self, path: &str, params: ListParams) -> Paginator<'_, R>
    where
        R: DeserializeOwned + Cursored,
    {
        Paginator::new(self, path, params)
    }

    /// Drain a collection into memory. Guard rail included: callers that ask
    /// for an unbounded list of a large resource usually did not mean to.
    pub fn list_all<R>(&self, path: &str, params: ListParams, cap: usize) -> Result<Vec<R>, Error>
    where
        R: DeserializeOwned + Cursored,
    {
        let mut out = Vec::new();
        for item in self.list::<R>(path, params) {
            out.push(item?);
            if out.len() >= cap {
                break;
            }
        }
        Ok(out)
    }

    // ---- core ------------------------------------------------------------

    /// Everything above funnels through here: build the request, run it under
    /// the retry policy, decode the body into `R`.
    pub fn send<B: Serialize, R: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        query: &[(String, String)],
        body: Option<&B>,
        idempotency_key: Option<&str>,
    ) -> Result<R, Error> {
        let payload = match body {
            Some(value) => Some(serde_json::to_vec(value).map_err(Error::Encode)?),
            None => None,
        };
        let url = self.build_url(path, query);

        let response = with_retry(&self.retry, |attempt| {
            let request = Request {
                method,
                url: url.clone(),
                headers: self.headers(idempotency_key, attempt, payload.is_some()),
                body: payload.clone(),
                timeout: self.timeout,
            };
            let response = self.transport.execute(request)?;
            interpret(response, path)
        })?;

        decode(response, path)
    }

    fn build_url(&self, path: &str, query: &[(String, String)]) -> String {
        let mut url = format!("{}{}", self.base_url, path);
        if !query.is_empty() {
            url.push('?');
            for (index, (key, value)) in query.iter().enumerate() {
                if index > 0 {
                    url.push('&');
                }
                url.push_str(&percent_encode(key));
                url.push('=');
                url.push_str(&percent_encode(value));
            }
        }
        url
    }

    fn headers(&self, idempotency_key: Option<&str>, attempt: u32, has_body: bool) -> Vec<(String, String)> {
        let mut headers = vec![
            ("Authorization".to_string(), format!("Bearer {}", self.api_key)),
            ("Billing-Version".to_string(), API_VERSION.to_string()),
            ("User-Agent".to_string(), USER_AGENT.to_string()),
            ("Accept".to_string(), "application/json".to_string()),
        ];
        if has_body {
            headers.push(("Content-Type".to_string(), "application/json".to_string()));
        }
        if let Some(key) = idempotency_key {
            headers.push(("Idempotency-Key".to_string(), key.to_string()));
        }
        if attempt > 1 {
            // Lets the provider's support team correlate duplicate deliveries.
            headers.push(("Billing-Retry-Attempt".to_string(), attempt.to_string()));
        }
        if let Some(account) = &self.account {
            headers.push(("Billing-Account".to_string(), account.clone()));
        }
        headers
    }
}

/// Turn a non-2xx response into the right `Error` variant, leaving successes
/// untouched for the decoder.
fn interpret(response: Response, path: &str) -> Result<Response, Error> {
    if response.is_success() {
        return Ok(response);
    }

    let request_id = response.header("Billing-Request-Id").map(str::to_string);

    if response.status == 429 {
        let retry_after = response
            .header("Retry-After")
            .and_then(|v| v.parse::<u64>().ok())
            .map(Duration::from_secs)
            .unwrap_or_else(|| Duration::from_secs(1));
        return Err(Error::RateLimited { retry_after, request_id });
    }

    #[derive(serde::Deserialize)]
    struct Envelope {
        error: ApiError,
    }

    let mut api_error = match serde_json::from_slice::<Envelope>(&response.body) {
        Ok(envelope) => envelope.error,
        Err(_) => ApiError {
            kind: Default::default(),
            code: String::new(),
            message: String::from_utf8_lossy(&response.body)
                .chars()
                .take(512)
                .collect(),
            param: None,
            doc_url: None,
            status: 0,
            request_id: None,
        },
    };
    api_error.status = response.status;
    api_error.request_id = request_id;

    if api_error.message.is_empty() {
        api_error.message = format!("{} returned {}", path, response.status);
    }

    Err(Error::Api(api_error))
}

/// Decode a successful body into `R`.
///
/// `204 No Content` and empty bodies are decoded as JSON `null`, which is what
/// `Option<_>` and unit-like response types expect.
fn decode<R: DeserializeOwned>(response: Response, path: &str) -> Result<R, Error> {
    let body: &[u8] = if response.body.is_empty() { b"null" } else { &response.body };
    serde_json::from_slice::<R>(body).map_err(|source| Error::Decode {
        path: path.to_string(),
        status: response.status,
        source,
    })
}

/// 128 bits of monotonic-plus-random, hex encoded. Unique enough that the
/// provider will treat two of our requests as distinct, stable enough that a
/// retry within one `send` call reuses the same key.
fn new_idempotency_key() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    let mixed = nanos ^ seq.wrapping_mul(0x9E37_79B9_7F4A_7C15);

    format!("idm_{:016x}{:016x}", nanos, mixed)
}

fn percent_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{:02X}", byte)),
        }
    }
    out
}
