//! Own the worker outside any future that recovery cancellation can drop.
use super::*;
use auth::cancellation::Cancellation;
use tokio::task::JoinHandle;

type Approval = Result<webauthn_rs_proto::PublicKeyCredential, InitError>;

#[derive(Default)]
pub(super) struct NativeApproval {
    cancel: Cancellation,
    task: Option<JoinHandle<Approval>>,
}

impl NativeApproval {
    pub(super) async fn run<T>(
        deadline: Duration,
        operation: impl AsyncFnOnce(&mut Self) -> Result<T, InitError>,
    ) -> Result<T, InitError> {
        let mut native = Self::default();
        let result = tokio::select! {
            biased;
            _ = tokio::signal::ctrl_c() => Err(InitError::invalid("release cancelled")),
            _ = tokio::time::sleep(deadline) => Err(InitError::invalid("release attempt expired; start a fresh attempt")),
            result = operation(&mut native) => result,
        };
        native.cancel_and_join().await;
        result
    }

    pub(super) async fn approve(
        &mut self,
        client: ApiClient,
        options: auth::LoginBeginResponse,
    ) -> Approval {
        let cancel = self.cancel.clone();
        self.task = Some(tokio::task::spawn_blocking(move || {
            let assertion =
                auth::get_assertion_cancellable(&client, &options, &client.frontend_url(), &cancel)
                    .with_context(Ctx::new("native release approval"))?;
            cancel
                .check()
                .with_context(Ctx::new("native approval cancelled"))?;
            serde_json::from_slice(&assertion.response_json)
                .with_context(Ctx::new("native assertion"))
        }));
        self.wait().await
    }

    async fn wait(&mut self) -> Approval {
        let result = self.task.as_mut().expect("approval worker started").await;
        self.task = None;
        self.cancel
            .check()
            .with_context(Ctx::new("native approval cancelled"))?;
        result.with_context(Ctx::new("native approval task"))?
    }

    pub(super) async fn cancel_and_join(&mut self) {
        self.cancel.cancel();
        if let Some(task) = self.task.take() {
            // The caller retains its timeout/disconnection error. Awaiting the
            // worker ensures its input guard has restored the terminal first.
            let _ = task.await;
        }
    }
}

impl Drop for NativeApproval {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

#[cfg(test)]
#[path = "native_approval_tests.rs"]
mod tests;
