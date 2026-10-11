use super::*;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

fn credential() -> webauthn_rs_proto::PublicKeyCredential {
    serde_json::from_value(json!({
        "id":"AQ", "rawId":"AQ", "type":"public-key", "extensions":{},
        "response":{"authenticatorData":"AQ", "clientDataJSON":"AQ", "signature":"AQ", "userHandle":null}
    })).unwrap()
}

#[tokio::test]
async fn cancellation_rejects_a_completed_approval() {
    let mut native = RecoveryApproval::default();
    native.task = Some(tokio::task::spawn_blocking(|| Ok(credential())));
    while !native.task.as_ref().unwrap().is_finished() {
        tokio::task::yield_now().await;
    }
    native.cancel.cancel();
    assert!(native.wait().await.is_err());
    native.cancel_and_join().await;
    assert!(native.task.is_none());
}

#[test]
fn cancelled_input_never_opens_a_terminal() {
    let cancel = Cancellation::default();
    cancel.cancel();
    for result in [
        cancel.password("must not appear"),
        cancel.selection("must not appear").map(|n| n.to_string()),
    ] {
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::Interrupted);
    }
}

#[tokio::test]
async fn deadline_joins_the_worker_before_returning() {
    let finished = Arc::new(AtomicBool::new(false));
    let result = RecoveryApproval::run(Duration::from_millis(30), async |native| {
        let cancel = native.cancel.clone();
        let finished = finished.clone();
        native.task = Some(tokio::task::spawn_blocking(move || {
            while cancel.check().is_ok() {
                std::thread::sleep(Duration::from_millis(5));
            }
            // Make it observable if run returns before the worker finishes.
            std::thread::sleep(Duration::from_millis(30));
            finished.store(true, Ordering::Release);
            Err(InitError::invalid("cancelled worker"))
        }));
        native.wait().await
    })
    .await;
    assert!(result.unwrap_err().to_string().contains("expired"));
    assert!(finished.load(Ordering::Acquire));
}

// The PTY harness runs this separately for each scenario. The approval worker
// uses production input and lifetime management, without needing a USB key.
#[tokio::test]
#[ignore = "driven by tests/native_approval_pty.py with a controlling terminal"]
async fn terminal_driver() {
    let scenario = std::env::var("CAUTION_NATIVE_APPROVAL_TEST").unwrap();
    let finished = Arc::new(AtomicBool::new(false));
    let deadline = if scenario == "timeout" {
        Duration::from_secs(1)
    } else {
        Duration::from_secs(8)
    };
    let relay = relay_server(false).await;
    eprintln!("Existing release summary");
    let result = RecoveryApproval::run(deadline, async |native| {
        relay.register(native);
        let cancel = native.cancel.clone();
        let done = finished.clone();
        let selection = scenario.starts_with("selection");
        native.task = Some(tokio::task::spawn_blocking(move || {
            let result = if selection {
                cancel.selection("Selection: ").map(|n| { assert_eq!(n, 1); })
            } else {
                cancel.password("PIN: ").map(|pin| {
                    let pin = zeroize::Zeroizing::new(pin);
                    assert_eq!(&*pin, "654321");
                })
            };
            assert!(!crossterm::terminal::is_raw_mode_enabled().unwrap());
            done.store(true, Ordering::Release);
            result.with_context(Ctx::new("native input"))?;
            cancel.check().with_context(Ctx::new("native input cancelled"))?;
            Ok(credential())
        }));
        let approval = if scenario == "disconnect" || scenario == "selection_cancel" {
            // A destination EOF cancels the same borrowed wait future.
            use tokio::io::AsyncReadExt;
            let (mut reader, writer) = tokio::io::duplex(1);
            let close = tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(1)).await;
                drop(writer);
            });
            let mut byte = [0];
            let result = tokio::select! {
                biased;
                _ = reader.read(&mut byte) => Err(InitError::invalid("destination disconnected; start a fresh attempt")),
                result = native.wait() => result,
            };
            close.abort();
            result
        } else {
            native.wait().await
        }?;
        eprintln!("Submission reached");
        Ok(approval)
    }).await;
    assert!(
        finished.load(Ordering::Acquire),
        "approval worker was detached"
    );
    match scenario.as_str() {
        "success" | "selection_success" => assert!(result.is_ok()),
        "timeout" => assert!(result.unwrap_err().to_string().contains("expired")),
        "disconnect" | "selection_cancel" => {
            assert!(result.unwrap_err().to_string().contains("disconnected"))
        }
        "ctrl_c" | "sigint" | "eof" => assert!(result.is_err()),
        _ => panic!("unknown PTY scenario"),
    }
    assert!(
        !relay.active.load(Ordering::SeqCst),
        "relay cleanup was detached"
    );
    eprintln!("Worker finished; terminal restored");
    // Mirror the CLI's abrupt exit after recovery has returned an error.
    if scenario != "success" && scenario != "selection_success" {
        std::process::exit(1);
    }
}

struct RelayServer {
    client: reqwest::Client,
    url: String,
    active: Arc<AtomicBool>,
    calls: Arc<std::sync::atomic::AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for RelayServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl RelayServer {
    fn register(&self, approval: &mut RecoveryApproval) {
        approval.relay = Some((
            self.client.clone(),
            [self.url.as_str(), "/cancel"].concat(),
            "requester".into(),
        ));
    }
}
async fn relay_server(stall: bool) -> RelayServer {
    use axum::{http::StatusCode, routing::post, Json, Router};
    let active = Arc::new(AtomicBool::new(true));
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let pending = active.clone();
    let count = calls.clone();
    let read = active.clone();
    let finish = active.clone();
    let app = Router::new()
        .route(
            "/cancel",
            post(move |Json(body): Json<Value>| {
                let pending = pending.clone();
                let count = count.clone();
                async move {
                    assert_eq!(body["token"], "requester");
                    count.fetch_add(1, Ordering::SeqCst);
                    if stall {
                        tokio::time::sleep(Duration::from_secs(10)).await;
                    }
                    pending.store(false, Ordering::SeqCst);
                    StatusCode::NO_CONTENT
                }
            }),
        )
        .route(
            "/read",
            post(move || {
                let read = read.clone();
                async move {
                    if read.load(Ordering::SeqCst) {
                        StatusCode::OK
                    } else {
                        StatusCode::GONE
                    }
                }
            }),
        )
        .route(
            "/finish",
            post(move || {
                let finish = finish.clone();
                async move {
                    if finish.load(Ordering::SeqCst) {
                        StatusCode::OK
                    } else {
                        StatusCode::GONE
                    }
                }
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = ["http://", &listener.local_addr().unwrap().to_string()].concat();
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    RelayServer {
        client: reqwest::Client::builder().no_proxy().build().unwrap(),
        url,
        active,
        calls,
        task,
    }
}

#[tokio::test]
async fn deadline_cancels_browser_before_returning_without_submission() {
    let relay = relay_server(false).await;
    let submitted = AtomicBool::new(false);
    let result = RecoveryApproval::run(Duration::from_millis(30), async |approval| {
        relay.register(approval);
        std::future::pending::<()>().await;
        submitted.store(true, Ordering::SeqCst);
        Ok(())
    })
    .await;
    assert!(result.unwrap_err().to_string().contains("expired"));
    assert!(!submitted.load(Ordering::SeqCst));
    assert_eq!(relay.calls.load(Ordering::SeqCst), 1);
    for endpoint in ["/read", "/finish"] {
        assert_eq!(
            relay
                .client
                .post([relay.url.as_str(), endpoint].concat())
                .send()
                .await
                .unwrap()
                .status(),
            reqwest::StatusCode::GONE
        );
    }
}

#[tokio::test]
async fn browser_cleanup_preserves_success_and_original_errors() {
    for error in [
        None,
        Some("destination disconnected"),
        Some("poll failed"),
        Some("unexpected approval origin"),
        Some("browser cancelled"),
    ] {
        let relay = relay_server(false).await;
        let result = RecoveryApproval::run(Duration::from_secs(5), async |approval| {
            relay.register(approval);
            match error {
                Some(message) => Err(InitError::invalid(message)),
                None => Ok(()),
            }
        })
        .await;
        if let Some(message) = error {
            assert!(result.unwrap_err().to_string().contains(message));
        } else {
            assert!(result.is_ok());
        }
        assert!(!relay.active.load(Ordering::SeqCst));
        assert_eq!(relay.calls.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn stalled_relay_cleanup_is_bounded_and_preserves_cancellation() {
    let relay = relay_server(true).await;
    let started = std::time::Instant::now();
    let result: Result<(), InitError> =
        RecoveryApproval::run(Duration::from_millis(30), async |approval| {
            relay.register(approval);
            std::future::pending().await
        })
        .await;
    assert!(result.unwrap_err().to_string().contains("expired"));
    assert_eq!(relay.calls.load(Ordering::SeqCst), 1);
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[tokio::test]
async fn expired_deadline_wins_over_a_ready_browser_approval() {
    let relay = relay_server(false).await;
    let submitted = AtomicBool::new(false);
    let result = RecoveryApproval::run(Duration::from_millis(10), async |approval| {
        relay.register(approval);
        // Resume with both branches ready: cancellation must win before submission.
        std::thread::sleep(Duration::from_millis(30));
        tokio::task::yield_now().await;
        submitted.store(true, Ordering::SeqCst);
        Ok(())
    }).await;
    assert!(result.unwrap_err().to_string().contains("expired"));
    assert!(!submitted.load(Ordering::SeqCst));
    assert!(!relay.active.load(Ordering::SeqCst));
}
