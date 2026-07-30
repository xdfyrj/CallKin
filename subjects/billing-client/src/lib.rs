//! Blocking client for the Billing API.
//!
//! ```no_run
//! use std::sync::Arc;
//! use billing_client::{Client, ListParams};
//! # use billing_client::http::MockTransport;
//!
//! let client = Client::builder(std::env::var("BILLING_API_KEY").unwrap())
//!     .transport(Arc::new(MockTransport::new()))
//!     .build();
//!
//! for invoice in client.invoices(ListParams::new().limit(100)) {
//!     let invoice = invoice?;
//!     println!("{} owes {}", invoice.customer, invoice.outstanding());
//! }
//! # Ok::<(), billing_client::Error>(())
//! ```
//!
//! Bring your own HTTP stack by implementing [`http::Transport`]. The SDK does
//! no networking of its own, which keeps it free of a runtime dependency and
//! makes every call path testable without a live endpoint.

pub mod client;
pub mod error;
pub mod http;
pub mod page;
pub mod resources;
pub mod retry;
pub mod webhook;

pub use client::{Client, ClientBuilder, API_VERSION};
pub use error::{ApiError, ApiErrorKind, Error, TransportError};
pub use page::{Cursored, ListParams, Page, Paginator};
pub use resources::{
    Charge, CreateCharge, CreateCustomer, CreateRefund, Customer, Invoice, InvoiceStatus, LineItem,
    Metadata, Refund, UpdateCustomer,
};
pub use retry::RetryPolicy;
pub use webhook::{Event, WebhookError, WebhookVerifier};
