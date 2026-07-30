//! HTTP/1.1 transport that talks to the local egress proxy.
//!
//! TLS, connection pooling, and outbound policy are the sidecar's job, so this
//! only has to speak plaintext HTTP/1.1 over a loopback socket. If you run
//! without a mesh, swap this out for a `ureq` or `reqwest::blocking` transport —
//! the SDK only needs the `Transport` trait.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use billing_client::error::TransportError;
use billing_client::http::{Request, Response, Transport};

pub struct ProxyTransport {
    /// `host:port` of the egress sidecar.
    proxy_addr: String,
    /// Value to send as `Host`, since the proxy routes on it.
    upstream_host: String,
}

impl ProxyTransport {
    pub fn new(proxy_addr: impl Into<String>, upstream_host: impl Into<String>) -> Self {
        ProxyTransport { proxy_addr: proxy_addr.into(), upstream_host: upstream_host.into() }
    }

    fn connect(&self, timeout: Duration) -> Result<TcpStream, TransportError> {
        let stream = TcpStream::connect(&self.proxy_addr)
            .map_err(|_| TransportError::Connect(self.proxy_addr.clone()))?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;
        stream.set_nodelay(true)?;
        Ok(stream)
    }
}

impl Transport for ProxyTransport {
    fn execute(&self, request: Request) -> Result<Response, TransportError> {
        let mut stream = self.connect(request.timeout)?;

        let target = request
            .url
            .split_once("://")
            .and_then(|(_, rest)| rest.split_once('/'))
            .map(|(_, tail)| format!("/{}", tail))
            .unwrap_or_else(|| "/".to_string());

        let mut head = format!("{} {} HTTP/1.1\r\n", request.method.as_str(), target);
        head.push_str(&format!("Host: {}\r\n", self.upstream_host));
        head.push_str("Connection: close\r\n");
        for (name, value) in &request.headers {
            head.push_str(&format!("{}: {}\r\n", name, value));
        }
        let body = request.body.unwrap_or_default();
        head.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));

        stream.write_all(head.as_bytes())?;
        if !body.is_empty() {
            stream.write_all(&body)?;
        }
        stream.flush()?;

        read_response(BufReader::new(stream))
    }
}

fn read_response<R: Read>(mut reader: BufReader<R>) -> Result<Response, TransportError> {
    let mut status_line = String::new();
    if reader.read_line(&mut status_line)? == 0 {
        return Err(TransportError::IncompleteResponse);
    }
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .ok_or(TransportError::IncompleteResponse)?;

    let mut headers = Vec::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            return Err(TransportError::IncompleteResponse);
        }
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_string(), value.trim().to_string()));
        }
    }

    let lookup = |name: &str| {
        headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    };

    let chunked = lookup("Transfer-Encoding")
        .map(|v| v.eq_ignore_ascii_case("chunked"))
        .unwrap_or(false);
    let content_length = lookup("Content-Length").and_then(|v| v.parse::<usize>().ok());

    let body = if chunked {
        read_chunked(&mut reader)?
    } else if let Some(length) = content_length {
        let mut buffer = vec![0u8; length];
        reader.read_exact(&mut buffer)?;
        buffer
    } else {
        let mut buffer = Vec::new();
        reader.read_to_end(&mut buffer)?;
        buffer
    };

    Ok(Response { status, headers, body })
}

fn read_chunked<R: Read>(reader: &mut BufReader<R>) -> Result<Vec<u8>, TransportError> {
    let mut body = Vec::new();
    loop {
        let mut size_line = String::new();
        if reader.read_line(&mut size_line)? == 0 {
            return Err(TransportError::IncompleteResponse);
        }
        // Chunk extensions after ';' are legal and ignorable.
        let size_token = size_line.trim().split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_token, 16)
            .map_err(|_| TransportError::IncompleteResponse)?;
        if size == 0 {
            break;
        }
        let mut chunk = vec![0u8; size];
        reader.read_exact(&mut chunk)?;
        body.extend_from_slice(&chunk);

        let mut crlf = [0u8; 2];
        reader.read_exact(&mut crlf)?;
    }
    Ok(body)
}
