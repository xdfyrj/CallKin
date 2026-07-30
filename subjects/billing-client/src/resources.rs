use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::client::Client;
use crate::error::Error;
use crate::page::{Cursored, ListParams, Paginator};

pub type Metadata = BTreeMap<String, String>;

// ---------------------------------------------------------------- customers

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Customer {
    pub id: String,
    pub email: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    /// Unix seconds.
    pub created: i64,
    #[serde(default)]
    pub currency: Option<String>,
    /// Negative means the customer has credit.
    #[serde(default)]
    pub balance: i64,
    #[serde(default)]
    pub delinquent: bool,
    #[serde(default)]
    pub metadata: Metadata,
}

impl Cursored for Customer {
    fn cursor(&self) -> &str {
        &self.id
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct CreateCustomer {
    pub email: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub currency: Option<String>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: Metadata,
}

impl CreateCustomer {
    pub fn new(email: impl Into<String>) -> Self {
        CreateCustomer { email: email.into(), ..Default::default() }
    }

    pub fn named(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    pub fn tag(mut self, key: &str, value: impl Into<String>) -> Self {
        self.metadata.insert(key.to_string(), value.into());
        self
    }
}

/// Every field optional: absent means "leave alone", which is why `metadata`
/// is skipped when empty rather than sent as `{}`.
#[derive(Debug, Clone, Default, Serialize)]
pub struct UpdateCustomer {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: Metadata,
}

// ----------------------------------------------------------------- invoices

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Invoice {
    pub id: String,
    pub customer: String,
    pub status: InvoiceStatus,
    /// Minor units, e.g. cents.
    pub amount_due: i64,
    #[serde(default)]
    pub amount_paid: i64,
    pub currency: String,
    pub created: i64,
    #[serde(default)]
    pub due_date: Option<i64>,
    #[serde(default)]
    pub lines: Vec<LineItem>,
    #[serde(default)]
    pub metadata: Metadata,
}

impl Invoice {
    pub fn outstanding(&self) -> i64 {
        (self.amount_due - self.amount_paid).max(0)
    }

    pub fn is_overdue(&self, now: i64) -> bool {
        matches!(self.status, InvoiceStatus::Open)
            && self.due_date.map(|due| due < now).unwrap_or(false)
    }
}

impl Cursored for Invoice {
    fn cursor(&self) -> &str {
        &self.id
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvoiceStatus {
    Draft,
    Open,
    Paid,
    Void,
    Uncollectible,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LineItem {
    pub id: String,
    pub description: String,
    pub quantity: u32,
    pub unit_amount: i64,
    #[serde(default)]
    pub proration: bool,
}

// ------------------------------------------------------------------ charges

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Charge {
    pub id: String,
    pub customer: String,
    pub amount: i64,
    pub currency: String,
    pub created: i64,
    #[serde(default)]
    pub captured: bool,
    #[serde(default)]
    pub refunded: bool,
    #[serde(default)]
    pub failure_code: Option<String>,
    #[serde(default)]
    pub invoice: Option<String>,
    #[serde(default)]
    pub metadata: Metadata,
}

impl Cursored for Charge {
    fn cursor(&self) -> &str {
        &self.id
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct CreateCharge {
    pub customer: String,
    pub amount: i64,
    pub currency: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invoice: Option<String>,
    /// False places an authorisation hold to be captured later.
    pub capture: bool,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: Metadata,
}

impl CreateCharge {
    /// `amount` is in the currency's minor unit.
    pub fn new(customer: impl Into<String>, amount: i64, currency: impl Into<String>) -> Self {
        CreateCharge {
            customer: customer.into(),
            amount,
            currency: currency.into(),
            description: None,
            invoice: None,
            capture: true,
            metadata: Metadata::new(),
        }
    }

    pub fn against_invoice(mut self, invoice_id: impl Into<String>) -> Self {
        self.invoice = Some(invoice_id.into());
        self
    }

    pub fn describe(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    pub fn tag(mut self, key: &str, value: impl Into<String>) -> Self {
        self.metadata.insert(key.to_string(), value.into());
        self
    }

    /// Hold the funds without settling; capture within seven days.
    pub fn authorize_only(mut self) -> Self {
        self.capture = false;
        self
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct CreateRefund {
    pub charge: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct Refund {
    pub id: String,
    pub charge: String,
    pub amount: i64,
    pub currency: String,
    pub created: i64,
    #[serde(default)]
    pub status: String,
}

// ------------------------------------------------------------- API surfaces

impl Client {
    pub fn create_customer(&self, request: &CreateCustomer) -> Result<Customer, Error> {
        self.post("/v1/customers", request)
    }

    /// Create using a caller-owned key so a crashed worker that replays the job
    /// gets the original customer back instead of a duplicate.
    pub fn create_customer_keyed(
        &self,
        request: &CreateCustomer,
        idempotency_key: &str,
    ) -> Result<Customer, Error> {
        self.post_idempotent("/v1/customers", request, idempotency_key)
    }

    pub fn get_customer(&self, id: &str) -> Result<Customer, Error> {
        self.get(&format!("/v1/customers/{}", id))
    }

    pub fn update_customer(&self, id: &str, request: &UpdateCustomer) -> Result<Customer, Error> {
        self.post(&format!("/v1/customers/{}", id), request)
    }

    pub fn delete_customer(&self, id: &str) -> Result<Deleted, Error> {
        self.delete(&format!("/v1/customers/{}", id))
    }

    pub fn customers(&self, params: ListParams) -> Paginator<'_, Customer> {
        self.list("/v1/customers", params)
    }

    pub fn get_invoice(&self, id: &str) -> Result<Invoice, Error> {
        self.get(&format!("/v1/invoices/{}", id))
    }

    pub fn invoices(&self, params: ListParams) -> Paginator<'_, Invoice> {
        self.list("/v1/invoices", params)
    }

    /// Invoices for one customer, newest first.
    pub fn invoices_for(&self, customer_id: &str, params: ListParams) -> Paginator<'_, Invoice> {
        self.list("/v1/invoices", params.filter("customer", customer_id))
    }

    pub fn void_invoice(&self, id: &str) -> Result<Invoice, Error> {
        self.post(&format!("/v1/invoices/{}/void", id), &EmptyBody {})
    }

    pub fn mark_uncollectible(&self, id: &str) -> Result<Invoice, Error> {
        self.post(&format!("/v1/invoices/{}/mark_uncollectible", id), &EmptyBody {})
    }

    pub fn create_charge(&self, request: &CreateCharge) -> Result<Charge, Error> {
        self.post("/v1/charges", request)
    }

    /// Charge under a caller-owned key. Batch jobs derive the key from the run
    /// identifier so a restart cannot double-charge.
    pub fn create_charge_keyed(
        &self,
        request: &CreateCharge,
        idempotency_key: &str,
    ) -> Result<Charge, Error> {
        self.post_idempotent("/v1/charges", request, idempotency_key)
    }

    pub fn get_charge(&self, id: &str) -> Result<Charge, Error> {
        self.get(&format!("/v1/charges/{}", id))
    }

    pub fn charges(&self, params: ListParams) -> Paginator<'_, Charge> {
        self.list("/v1/charges", params)
    }

    pub fn refund(&self, request: &CreateRefund) -> Result<Refund, Error> {
        self.post("/v1/refunds", request)
    }
}

/// Response shape for deletes.
#[derive(Debug, Clone, Deserialize)]
pub struct Deleted {
    pub id: String,
    #[serde(default)]
    pub deleted: bool,
}

/// `{}` — some endpoints take an action with no parameters.
#[derive(Debug, Clone, Serialize)]
pub struct EmptyBody {}
