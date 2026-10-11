use super::*;
use axum::{
    Json, Router,
    http::StatusCode,
    middleware,
    response::{IntoResponse, Response},
    routing::post,
};
use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Instant,
};

// Exercise the gateway's actual shared IP budget, not a copy of its constants.
#[allow(dead_code)]
#[path = "../../../gateway/src/rate_limit.rs"]
mod rate_limit;

type Calls = Arc<Mutex<Vec<(Instant, Value)>>>;
struct Mock {
    url: String,
    calls: Calls,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Mock {
    fn drop(&mut self) {
        self.task.abort();
    }
}
async fn server(
    reply: impl Fn(usize, &Value) -> Response + Send + Sync + 'static,
    shared_budget: bool,
) -> Mock {
    let calls: Calls = Arc::default();
    let recorded = calls.clone();
    let reply = Arc::new(reply);
    let mut app = Router::new().route(
        "/status",
        post(move |Json(body): Json<Value>| {
            let calls = recorded.clone();
            let reply = reply.clone();
            async move {
                let mut calls = calls.lock().unwrap();
                calls.push((Instant::now(), body.clone()));
                reply(calls.len() - 1, &body)
            }
        }),
    );
    if shared_budget {
        let limiter = rate_limit::RateLimiter::new(
            rate_limit::GLOBAL_MAX_REQUESTS,
            rate_limit::GLOBAL_WINDOW_SECS,
        );
        // Leave room for the browser's approval calls and other auth traffic.
        for _ in 0..10 {
            assert!(limiter.check_rate_limit("127.0.0.1").await);
        }
        app = app.layer(middleware::from_fn_with_state(
            limiter,
            rate_limit::rate_limit_middleware,
        ));
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/status", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });
    Mock { url, calls, task }
}
fn complete() -> Response {
    Json(json!({"status":"complete", "assertion": {
        "id":"AQ", "rawId":"AQ", "type":"public-key", "extensions":{},
        "response":{"authenticatorData":"AQ", "clientDataJSON":"AQ", "signature":"AQ", "userHandle":null}
    }})).into_response()
}
fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap()
}

#[tokio::test]
async fn throttling_backs_off_caps_and_resets_without_replacing_token() {
    let mock = server(
        |n, _| match n {
            0..=3 => (StatusCode::TOO_MANY_REQUESTS, "throttled").into_response(),
            4 => Json(json!({"status":"pending"})).into_response(),
            _ => complete(),
        },
        false,
    )
    .await;
    let started = Instant::now();
    let credential = tokio::time::timeout(
        Duration::from_secs(75),
        poll_browser_assertion(&client(), &mock.url, "same-token"),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(credential.id, "AQ");
    let calls = mock.calls.lock().unwrap();
    assert_eq!(calls.len(), 6);
    let mut previous = started;
    for ((at, body), seconds) in calls.iter().zip([2, 4, 8, 16, 16, 2]) {
        assert!(*at - previous >= Duration::from_secs(seconds));
        assert!(*at - previous < Duration::from_secs(seconds + 5));
        assert_eq!(body, &json!({"token":"same-token"}));
        previous = *at;
    }
}

#[tokio::test]
async fn persistent_throttling_obeys_the_callers_deadline() {
    let mock = server(|_, _| StatusCode::TOO_MANY_REQUESTS.into_response(), false).await;
    assert!(
        tokio::time::timeout(
            Duration::from_secs(7),
            poll_browser_assertion(&client(), &mock.url, "expired")
        )
        .await
        .is_err()
    );
    assert_eq!(mock.calls.lock().unwrap().len(), 2);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(mock.calls.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn non_throttling_errors_and_invalid_responses_are_terminal() {
    for status in [
        StatusCode::FORBIDDEN,
        StatusCode::GONE,
        StatusCode::INTERNAL_SERVER_ERROR,
        StatusCode::OK,
    ] {
        let mock = server(move |_, _| (status, "not JSON").into_response(), false).await;
        assert!(
            poll_browser_assertion(&client(), &mock.url, "token")
                .await
                .is_err()
        );
        assert_eq!(mock.calls.lock().unwrap().len(), 1);
    }
    let mock = server(
        |_, _| "x".repeat(2 * 1024 * 1024 + 1).into_response(),
        false,
    )
    .await;
    assert!(
        poll_browser_assertion(&client(), &mock.url, "token")
            .await
            .unwrap_err()
            .to_string()
            .contains("response too large")
    );
    assert_eq!(mock.calls.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn two_approvals_share_the_gateway_budget_for_over_a_minute() {
    let started = Instant::now();
    let mock = server(
        move |_, _| {
            if started.elapsed() < Duration::from_secs(61) {
                Json(json!({"status":"pending"})).into_response()
            } else {
                complete()
            }
        },
        true,
    )
    .await;
    let client = client();
    let approvals = async {
        tokio::try_join!(
            poll_browser_assertion(&client, &mock.url, "alice"),
            poll_browser_assertion(&client, &mock.url, "bob"),
        )
    };
    let (alice, bob) = tokio::time::timeout(Duration::from_secs(80), approvals)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(alice.id, "AQ");
    assert_eq!(bob.id, "AQ");
    let calls = mock.calls.lock().unwrap();
    assert!(calls.len() >= 50);
    for token in ["alice", "bob"] {
        assert!(
            calls
                .iter()
                .filter(|(_, body)| body["token"] == token)
                .count()
                >= 25
        );
    }
}
