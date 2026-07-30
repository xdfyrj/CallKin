use std::sync::Arc;
use std::time::Duration;

use billing_client::error::TransportError;
use billing_client::http::{Method, MockTransport, Response};
use billing_client::resources::{CreateCustomer, Customer, Invoice};
use billing_client::webhook::{sign_payload, WebhookError, WebhookVerifier};
use billing_client::{Client, Error, ListParams, RetryPolicy};

fn client_with(transport: Arc<MockTransport>) -> Client {
    Client::builder("sk_test_abc123")
        .base_url("https://api.test.local")
        .transport(transport)
        .retry(RetryPolicy {
            max_attempts: 3,
            initial_backoff: Duration::from_millis(1),
            max_backoff: Duration::from_millis(2),
            multiplier: 1.0,
            jitter: false,
        })
        .build()
}

#[test]
fn decodes_a_typed_resource() {
    let transport = Arc::new(MockTransport::new());
    transport.expect(
        Method::Get,
        "/v1/customers/cus_1",
        Response::new(
            200,
            r#"{"id":"cus_1","email":"ada@example.com","created":1700000000,"balance":-2500}"#,
        ),
    );

    let client = client_with(transport.clone());
    let customer = client.get_customer("cus_1").expect("customer decodes");

    assert_eq!(customer.id, "cus_1");
    assert_eq!(customer.balance, -2500);
    assert!(!customer.delinquent, "absent bool defaults to false");

    let request = &transport.requests()[0];
    assert_eq!(request.header("Authorization"), Some("Bearer sk_test_abc123"));
    assert_eq!(request.header("Billing-Version"), Some(billing_client::API_VERSION));
}

#[test]
fn post_attaches_an_idempotency_key_and_reuses_it_across_retries() {
    let transport = Arc::new(MockTransport::new());
    transport.expect(Method::Post, "/v1/customers", Response::new(503, r#"{"error":{"message":"upstream unavailable"}}"#));
    transport.expect(
        Method::Post,
        "/v1/customers",
        Response::new(200, r#"{"id":"cus_2","email":"grace@example.com","created":1700000001}"#),
    );

    let client = client_with(transport.clone());
    let created: Customer = client
        .create_customer(&CreateCustomer::new("grace@example.com").named("Grace"))
        .expect("succeeds on the second attempt");

    assert_eq!(created.id, "cus_2");
    assert_eq!(transport.call_count(), 2);

    let requests = transport.requests();
    let first = requests[0].header("Idempotency-Key").unwrap();
    let second = requests[1].header("Idempotency-Key").unwrap();
    assert_eq!(first, second, "a retry must not mint a new key");
    assert_eq!(requests[1].header("Billing-Retry-Attempt"), Some("2"));
}

#[test]
fn client_errors_are_not_retried() {
    let transport = Arc::new(MockTransport::new());
    transport.expect(
        Method::Post,
        "/v1/customers",
        Response::new(
            400,
            r#"{"error":{"type":"invalid_request","code":"email_invalid","message":"Not a valid address","param":"email"}}"#,
        )
        .with_header("Billing-Request-Id", "req_9f2"),
    );

    let client = client_with(transport.clone());
    let err = client
        .create_customer(&CreateCustomer::new("nonsense"))
        .expect_err("400 surfaces as an ApiError");

    match err {
        Error::Api(api) => {
            assert_eq!(api.status, 400);
            assert_eq!(api.code, "email_invalid");
            assert_eq!(api.param.as_deref(), Some("email"));
            assert_eq!(api.request_id.as_deref(), Some("req_9f2"));
        }
        other => panic!("expected Error::Api, got {:?}", other),
    }
    assert_eq!(transport.call_count(), 1, "4xx must not be retried");
}

#[test]
fn rate_limits_honour_retry_after_then_succeed() {
    let transport = Arc::new(MockTransport::new());
    transport.expect(
        Method::Get,
        "/v1/customers/cus_3",
        Response::new(429, "{}").with_header("Retry-After", "0"),
    );
    transport.expect(
        Method::Get,
        "/v1/customers/cus_3",
        Response::new(200, r#"{"id":"cus_3","email":"lin@example.com","created":1700000002}"#),
    );

    let client = client_with(transport.clone());
    assert_eq!(client.get_customer("cus_3").unwrap().id, "cus_3");
    assert_eq!(transport.call_count(), 2);
}

#[test]
fn retry_budget_is_finite() {
    let transport = Arc::new(MockTransport::new());
    for _ in 0..5 {
        transport.expect_failure(
            Method::Get,
            "/v1/customers/cus_4",
            TransportError::Timeout { elapsed: Duration::from_secs(30) },
        );
    }

    let client = client_with(transport.clone());
    let err = client.get_customer("cus_4").expect_err("gives up");

    assert!(matches!(err, Error::RetriesExhausted { attempts: 3, .. }));
    assert_eq!(transport.call_count(), 3);
}

#[test]
fn paginator_follows_cursors_and_stops() {
    let transport = Arc::new(MockTransport::new());
    transport.expect(
        Method::Get,
        "/v1/invoices",
        Response::new(
            200,
            r#"{"data":[
                {"id":"in_1","customer":"cus_1","status":"open","amount_due":1000,"currency":"usd","created":1},
                {"id":"in_2","customer":"cus_2","status":"open","amount_due":2000,"currency":"usd","created":2}
            ],"has_more":true,"next_cursor":"in_2"}"#,
        ),
    );
    transport.expect(
        Method::Get,
        "/v1/invoices",
        Response::new(
            200,
            r#"{"data":[
                {"id":"in_3","customer":"cus_3","status":"paid","amount_due":3000,"amount_paid":3000,"currency":"usd","created":3}
            ],"has_more":false}"#,
        ),
    );

    let client = client_with(transport.clone());
    let invoices: Vec<Invoice> = client
        .invoices(ListParams::new().limit(2))
        .collect::<Result<Vec<_>, _>>()
        .expect("both pages decode");

    assert_eq!(invoices.len(), 3);
    assert_eq!(invoices[2].outstanding(), 0);
    assert_eq!(transport.call_count(), 2);

    let second = &transport.requests()[1];
    assert!(second.url.contains("starting_after=in_2"), "cursor carried forward: {}", second.url);
}

#[test]
fn list_all_respects_its_cap() {
    let transport = Arc::new(MockTransport::new());
    transport.expect(
        Method::Get,
        "/v1/invoices",
        Response::new(
            200,
            r#"{"data":[
                {"id":"in_1","customer":"cus_1","status":"open","amount_due":1000,"currency":"usd","created":1},
                {"id":"in_2","customer":"cus_2","status":"open","amount_due":2000,"currency":"usd","created":2}
            ],"has_more":true,"next_cursor":"in_2"}"#,
        ),
    );

    let client = client_with(transport.clone());
    let invoices: Vec<Invoice> = client
        .list_all("/v1/invoices", ListParams::new(), 1)
        .expect("stops at the cap");

    assert_eq!(invoices.len(), 1);
    assert_eq!(transport.call_count(), 1, "no page is fetched past the cap");
}

#[test]
fn schema_drift_is_reported_as_a_decode_error() {
    let transport = Arc::new(MockTransport::new());
    transport.expect(
        Method::Get,
        "/v1/customers/cus_5",
        // `created` arrives as a string from a hypothetical future version.
        Response::new(200, r#"{"id":"cus_5","email":"x@example.com","created":"2026-01-01"}"#),
    );

    let client = client_with(transport);
    match client.get_customer("cus_5") {
        Err(Error::Decode { status, path, .. }) => {
            assert_eq!(status, 200);
            assert_eq!(path, "/v1/customers/cus_5");
        }
        other => panic!("expected a decode error, got {:?}", other),
    }
}

// ------------------------------------------------------------------ webhooks

const WEBHOOK_BODY: &str = r#"{
  "id": "evt_1",
  "type": "invoice.payment_failed",
  "created": 1730000000,
  "livemode": true,
  "data": {
    "object": {
      "id": "in_9",
      "customer": "cus_9",
      "status": "open",
      "amount_due": 4200,
      "amount_paid": 0,
      "currency": "eur",
      "created": 1729990000
    },
    "previous_attributes": { "status": "draft" }
  }
}"#;

#[test]
fn verifies_and_decodes_a_delivery() {
    let verifier = WebhookVerifier::new("whsec_test");
    let header = sign_payload("whsec_test", WEBHOOK_BODY.as_bytes(), 1730000000);

    let event = verifier
        .verify_at(WEBHOOK_BODY.as_bytes(), &header, 1730000010)
        .expect("signature is valid");

    assert!(event.is("invoice."));

    let invoice: Invoice = event.object().expect("object is an invoice");
    assert_eq!(invoice.id, "in_9");
    assert_eq!(invoice.outstanding(), 4200);

    let before: Option<Invoice> = event.previous().expect("previous state reconstructs");
    assert_eq!(before.unwrap().status, billing_client::InvoiceStatus::Draft);
}

#[test]
fn rejects_a_tampered_body() {
    let verifier = WebhookVerifier::new("whsec_test");
    let header = sign_payload("whsec_test", WEBHOOK_BODY.as_bytes(), 1730000000);
    let tampered = WEBHOOK_BODY.replace("4200", "1");

    assert!(matches!(
        verifier.verify_at(tampered.as_bytes(), &header, 1730000010),
        Err(WebhookError::NoMatch)
    ));
}

#[test]
fn rejects_a_replayed_delivery() {
    let verifier = WebhookVerifier::new("whsec_test").tolerance(Duration::from_secs(60));
    let header = sign_payload("whsec_test", WEBHOOK_BODY.as_bytes(), 1730000000);

    assert!(matches!(
        verifier.verify_at(WEBHOOK_BODY.as_bytes(), &header, 1730009999),
        Err(WebhookError::TooOld { .. })
    ));
}

#[test]
fn accepts_either_secret_during_rotation() {
    let verifier = WebhookVerifier::new("whsec_old").with_secret("whsec_new");

    for secret in ["whsec_old", "whsec_new"] {
        let header = sign_payload(secret, WEBHOOK_BODY.as_bytes(), 1730000000);
        assert!(
            verifier.verify_at(WEBHOOK_BODY.as_bytes(), &header, 1730000005).is_ok(),
            "{} should be accepted",
            secret
        );
    }
}

#[test]
fn wrong_object_type_is_an_error_not_a_panic() {
    let verifier = WebhookVerifier::new("whsec_test");
    let header = sign_payload("whsec_test", WEBHOOK_BODY.as_bytes(), 1730000000);
    let event = verifier.verify_at(WEBHOOK_BODY.as_bytes(), &header, 1730000001).unwrap();

    // The handler guessed wrong about what this event carries.
    let wrong: Result<Customer, _> = event.object();
    assert!(matches!(wrong, Err(WebhookError::UnexpectedObject { .. })));
}
