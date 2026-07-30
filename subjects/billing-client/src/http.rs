use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use crate::error::TransportError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Get,
    Post,
    Delete,
}

impl Method {
    pub fn as_str(&self) -> &'static str {
        match self {
            Method::Get => "GET",
            Method::Post => "POST",
            Method::Delete => "DELETE",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Request {
    pub method: Method,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
    pub timeout: Duration,
}

impl Request {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    pub fn new(status: u16, body: impl Into<Vec<u8>>) -> Self {
        Response { status, headers: Vec::new(), body: body.into() }
    }

    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_string(), value.to_string()));
        self
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

/// The seam between the SDK and whatever HTTP stack the host application
/// already runs. Implement this over `ureq`, `reqwest::blocking`, or a
/// connection pool you already own.
pub trait Transport: Send + Sync {
    fn execute(&self, request: Request) -> Result<Response, TransportError>;
}

impl<T: Transport + ?Sized> Transport for Box<T> {
    fn execute(&self, request: Request) -> Result<Response, TransportError> {
        (**self).execute(request)
    }
}

/// Canned-response transport for tests. Records every request it sees so
/// assertions can check headers, idempotency keys, and retry counts.
pub struct MockTransport {
    routes: Mutex<HashMap<String, Vec<Result<Response, TransportError>>>>,
    seen: Mutex<Vec<Request>>,
}

impl Default for MockTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl MockTransport {
    pub fn new() -> Self {
        MockTransport { routes: Mutex::new(HashMap::new()), seen: Mutex::new(Vec::new()) }
    }

    /// Queue a response for `METHOD /path`. Responses are consumed in order, so
    /// queueing twice lets a test exercise the retry path.
    pub fn expect(&self, method: Method, path: &str, response: Response) -> &Self {
        let key = format!("{} {}", method.as_str(), path);
        self.routes.lock().unwrap().entry(key).or_default().push(Ok(response));
        self
    }

    pub fn expect_failure(&self, method: Method, path: &str, error: TransportError) -> &Self {
        let key = format!("{} {}", method.as_str(), path);
        self.routes.lock().unwrap().entry(key).or_default().push(Err(error));
        self
    }

    pub fn requests(&self) -> Vec<Request> {
        self.seen.lock().unwrap().clone()
    }

    pub fn call_count(&self) -> usize {
        self.seen.lock().unwrap().len()
    }
}

impl Transport for MockTransport {
    fn execute(&self, request: Request) -> Result<Response, TransportError> {
        let path = request
            .url
            .split_once("://")
            .and_then(|(_, rest)| rest.split_once('/'))
            .map(|(_, tail)| format!("/{}", tail))
            .unwrap_or_else(|| request.url.clone());
        let path = path.split('?').next().unwrap_or(&path).to_string();
        let key = format!("{} {}", request.method.as_str(), path);

        self.seen.lock().unwrap().push(request);

        let mut routes = self.routes.lock().unwrap();
        match routes.get_mut(&key) {
            Some(queue) if !queue.is_empty() => queue.remove(0),
            _ => Err(TransportError::Connect(format!("no mock registered for {}", key))),
        }
    }
}
