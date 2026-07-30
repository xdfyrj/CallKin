//! Nightly dunning job.
//!
//! Walks open invoices that have passed their due date, re-attempts collection
//! once, and escalates anything still unpaid past the grace window. Designed to
//! be re-runnable: every mutating call carries an idempotency key derived from
//! the invoice id and the run date, so a crashed run can simply be restarted.
//!
//!   reconcile --run-date 2026-07-29 [--dry-run] [--limit 500]

mod transport;

use std::collections::BTreeMap;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use billing_client::{
    Client, CreateCharge, Customer, Error, Invoice, InvoiceStatus, ListParams, RetryPolicy,
};
use transport::ProxyTransport;

/// Invoices younger than this are left to the payment processor's own retries.
const GRACE_PERIOD: i64 = 3 * 86_400;
/// Past this, stop chasing and write it off.
const WRITE_OFF_AFTER: i64 = 45 * 86_400;
/// Do not auto-charge above this without a human looking at it.
const AUTO_CHARGE_CEILING: i64 = 500_00;

fn main() -> ExitCode {
    let opts = match Options::from_args(std::env::args().skip(1)) {
        Ok(opts) => opts,
        Err(message) => {
            eprintln!("{}", message);
            eprintln!("usage: reconcile --run-date <YYYY-MM-DD> [--dry-run] [--limit N]");
            return ExitCode::from(2);
        }
    };

    let client = match build_client() {
        Ok(client) => client,
        Err(message) => {
            eprintln!("startup failed: {}", message);
            return ExitCode::from(78); // EX_CONFIG
        }
    };

    match run(&client, &opts) {
        Ok(summary) => {
            println!("{}", summary.to_json());
            if summary.failed > 0 {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            }
        }
        Err(e) => {
            eprintln!(
                "reconciliation aborted: {}{}",
                e,
                e.request_id().map(|id| format!(" [request_id={}]", id)).unwrap_or_default()
            );
            ExitCode::from(1)
        }
    }
}

fn build_client() -> Result<Client, String> {
    let api_key = std::env::var("BILLING_API_KEY")
        .map_err(|_| "BILLING_API_KEY is not set".to_string())?;
    let proxy = std::env::var("EGRESS_PROXY").unwrap_or_else(|_| "127.0.0.1:15001".to_string());
    let upstream =
        std::env::var("BILLING_HOST").unwrap_or_else(|_| "api.billing.example.com".to_string());

    let transport = ProxyTransport::new(proxy, upstream.clone());

    Ok(Client::builder(api_key)
        .base_url(format!("http://{}", upstream))
        .transport(Arc::new(transport))
        // Batch job: we can afford to wait longer than an interactive path.
        .retry(RetryPolicy { max_attempts: 6, max_backoff: Duration::from_secs(20), ..Default::default() })
        .timeout(Duration::from_secs(45))
        .build())
}

struct Options {
    run_date: String,
    run_epoch: i64,
    dry_run: bool,
    limit: usize,
}

impl Options {
    fn from_args<I: Iterator<Item = String>>(mut args: I) -> Result<Self, String> {
        let mut run_date = None;
        let mut dry_run = false;
        let mut limit = 1_000usize;

        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--run-date" => run_date = args.next(),
                "--dry-run" => dry_run = true,
                "--limit" => {
                    limit = args
                        .next()
                        .and_then(|v| v.parse().ok())
                        .ok_or_else(|| "--limit expects a number".to_string())?;
                }
                other => return Err(format!("unrecognised argument: {}", other)),
            }
        }

        let run_date = run_date.ok_or_else(|| "--run-date is required".to_string())?;
        let run_epoch = parse_date(&run_date)?;
        Ok(Options { run_date, run_epoch, dry_run, limit })
    }
}

/// `YYYY-MM-DD` to Unix seconds at midnight UTC, via days-from-civil.
fn parse_date(input: &str) -> Result<i64, String> {
    let parts: Vec<&str> = input.split('-').collect();
    if parts.len() != 3 {
        return Err(format!("'{}' is not YYYY-MM-DD", input));
    }
    let year: i64 = parts[0].parse().map_err(|_| "bad year".to_string())?;
    let month: i64 = parts[1].parse().map_err(|_| "bad month".to_string())?;
    let day: i64 = parts[2].parse().map_err(|_| "bad day".to_string())?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return Err(format!("'{}' is not a valid date", input));
    }

    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let day_of_year = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era - 719_468;

    Ok(days * 86_400)
}

#[derive(Default)]
struct Summary {
    run_date: String,
    dry_run: bool,
    scanned: usize,
    skipped_in_grace: usize,
    charged: usize,
    charge_amount: i64,
    escalated: usize,
    written_off: usize,
    failed: usize,
    failures_by_code: BTreeMap<String, usize>,
}

impl Summary {
    fn to_json(&self) -> String {
        let payload = serde_json::json!({
            "event": "reconcile.completed",
            "run_date": self.run_date,
            "dry_run": self.dry_run,
            "scanned": self.scanned,
            "skipped_in_grace": self.skipped_in_grace,
            "charged": self.charged,
            "charge_amount_minor": self.charge_amount,
            "escalated": self.escalated,
            "written_off": self.written_off,
            "failed": self.failed,
            "failures_by_code": self.failures_by_code,
        });
        payload.to_string()
    }
}

fn run(client: &Client, opts: &Options) -> Result<Summary, Error> {
    let mut summary =
        Summary { run_date: opts.run_date.clone(), dry_run: opts.dry_run, ..Default::default() };

    // Only look back as far as the write-off horizon; older invoices have
    // already been dealt with by a previous run.
    let params = ListParams::new()
        .limit(100)
        .created_between(opts.run_epoch - WRITE_OFF_AFTER * 2, opts.run_epoch)
        .filter("status", "open");

    // Buffer the page walk before mutating, so a charge that changes an
    // invoice's status cannot disturb the cursor mid-iteration.
    let invoices: Vec<Invoice> = client.list_all("/v1/invoices", params, opts.limit)?;

    for invoice in invoices {
        summary.scanned += 1;

        if !invoice.is_overdue(opts.run_epoch) {
            continue;
        }
        let overdue_by = opts.run_epoch - invoice.due_date.unwrap_or(opts.run_epoch);
        if overdue_by < GRACE_PERIOD {
            summary.skipped_in_grace += 1;
            continue;
        }

        match decide(&invoice, overdue_by) {
            Action::WriteOff => {
                if !opts.dry_run {
                    client.mark_uncollectible(&invoice.id)?;
                }
                summary.written_off += 1;
                log_action("write_off", &invoice, opts.dry_run);
            }
            Action::Escalate(reason) => {
                summary.escalated += 1;
                log_escalation(&invoice, reason, client);
            }
            Action::Charge(amount) => {
                let request = CreateCharge::new(&invoice.customer, amount, &invoice.currency)
                    .against_invoice(&invoice.id)
                    .describe(format!("Automatic collection for {}", invoice.id))
                    .tag("reconcile_run", opts.run_date.clone())
                    .tag("invoice", invoice.id.clone());

                // Stable across reruns of the same night, so a restart cannot
                // charge the customer twice.
                let key = format!("reconcile:{}:{}", opts.run_date, invoice.id);

                if opts.dry_run {
                    summary.charged += 1;
                    summary.charge_amount += amount;
                    log_action("charge", &invoice, true);
                    continue;
                }

                match client.create_charge_keyed(&request, &key) {
                    Ok(charge) => {
                        summary.charged += 1;
                        summary.charge_amount += charge.amount;
                        log_action("charge", &invoice, false);
                    }
                    Err(Error::Api(api)) => {
                        summary.failed += 1;
                        *summary.failures_by_code.entry(api.code.clone()).or_insert(0) += 1;
                        eprintln!(
                            "{}",
                            serde_json::json!({
                                "event": "reconcile.charge_failed",
                                "invoice": invoice.id,
                                "customer": invoice.customer,
                                "code": api.code,
                                "message": api.message,
                                "request_id": api.request_id,
                            })
                        );
                    }
                    // Anything not attributable to this invoice — rate limits,
                    // transport, exhausted retries — means the run is unhealthy.
                    Err(other) => return Err(other),
                }
            }
        }
    }

    Ok(summary)
}

enum Action {
    Charge(i64),
    Escalate(&'static str),
    WriteOff,
}

fn decide(invoice: &Invoice, overdue_by: i64) -> Action {
    let outstanding = invoice.outstanding();

    if overdue_by > WRITE_OFF_AFTER {
        return Action::WriteOff;
    }
    if outstanding <= 0 || invoice.status != InvoiceStatus::Open {
        return Action::Escalate("invoice changed state since it was listed");
    }
    if outstanding > AUTO_CHARGE_CEILING {
        return Action::Escalate("outstanding balance above auto-charge ceiling");
    }
    if invoice.metadata.get("collection").map(String::as_str) == Some("manual") {
        return Action::Escalate("account flagged for manual collection");
    }
    Action::Charge(outstanding)
}

fn log_action(action: &str, invoice: &Invoice, dry_run: bool) {
    println!(
        "{}",
        serde_json::json!({
            "event": "reconcile.action",
            "action": action,
            "dry_run": dry_run,
            "invoice": invoice.id,
            "customer": invoice.customer,
            "outstanding_minor": invoice.outstanding(),
            "currency": invoice.currency,
        })
    );
}

/// Escalations carry the customer's contact details so the collections queue
/// does not have to re-query. A lookup failure downgrades the log line rather
/// than failing the run.
fn log_escalation(invoice: &Invoice, reason: &str, client: &Client) {
    let customer: Option<Customer> = client.get_customer(&invoice.customer).ok();
    eprintln!(
        "{}",
        serde_json::json!({
            "event": "reconcile.escalated",
            "invoice": invoice.id,
            "reason": reason,
            "outstanding_minor": invoice.outstanding(),
            "customer": invoice.customer,
            "email": customer.as_ref().map(|c| c.email.clone()),
            "delinquent": customer.as_ref().map(|c| c.delinquent),
        })
    );
}
