use super::*;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

fn credential() -> webauthn_rs_proto::PublicKeyCredential {
    serde_json::from_value(json!({
        "id":"AQ", "rawId":"AQ", "type":"public-key", "extensions":{},
        "response":{"authenticatorData":"AQ", "clientDataJSON":"AQ", "signature":"AQ", "userHandle":null}
    })).unwrap()
}

#[tokio::test]
async fn cancellation_rejects_a_completed_approval() {
    let mut native = NativeApproval::default();
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
    let result = NativeApproval::run(Duration::from_millis(30), async |native| {
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
    eprintln!("Existing release summary");
    let result = NativeApproval::run(deadline, async |native| {
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
    eprintln!("Worker finished; terminal restored");
    // Mirror the CLI's abrupt exit after recovery has returned an error.
    if scenario != "success" && scenario != "selection_success" {
        std::process::exit(1);
    }
}
