// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Local transport probes, not a reproduction of the observed ports-suite failure.
//! The database/API boundary is replaced by an explicitly released deployment;
//! channel-open/data/EOF use the real gateway handler and the wire uses russh.

use super::*;
use russh::server::Handler;
use std::time::Duration;
use tokio::sync::oneshot;

const WATCHDOG: Duration = Duration::from_secs(5);
const PROGRESS: &[u8] = b"remote: Checking fully managed capacity...";
const COMPLETE: &[u8] = b" Complete!\n";

fn local_server() -> SshServer {
    SshServer::new(
        sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://unused:unused@127.0.0.1/unused")
            .unwrap(),
        String::new(),
        String::new(),
        None,
    )
}

struct DelayedDeploy {
    gateway: SshSession,
    release: Option<oneshot::Receiver<()>>,
    finished: Option<oneshot::Sender<bool>>,
    eof_seen: Option<oneshot::Sender<()>>,
}

impl Handler for DelayedDeploy {
    type Error = SshHandlerError;

    async fn auth_none(&mut self, _user: &str) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        self.gateway.channel_open_session(channel, session).await
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.gateway.data(channel, data, session).await
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.gateway.channel_eof(channel, session).await?;
        if let Some(eof_seen) = self.eof_seen.take() {
            let _ = eof_seen.send(());
        }
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        _data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let release = self.release.take().unwrap();
        let finished = self.finished.take().unwrap();
        let handle = session.handle();
        tokio::spawn(async move {
            handle
                .extended_data(channel, 1, Bytes::from_static(PROGRESS))
                .await
                .unwrap();
            if release.await.is_ok() {
                let enqueued = handle
                    .extended_data(channel, 1, Bytes::from_static(COMPLETE))
                    .await
                    .is_ok();
                let _ = handle.exit_status_request(channel, 0).await;
                let _ = handle.close(channel).await;
                let _ = finished.send(enqueued);
            }
        });
        Ok(())
    }
}

struct LocalClient {
    progress_seen: Option<oneshot::Sender<()>>,
    resume: Option<oneshot::Receiver<()>>,
}

impl russh::client::Handler for LocalClient {
    type Error = russh::Error;

    async fn check_server_key(&mut self, _key: &PublicKey) -> Result<bool, Self::Error> {
        Ok(true)
    }

    async fn extended_data(
        &mut self,
        _channel: ChannelId,
        _ext: u32,
        _data: &[u8],
        _session: &mut russh::client::Session,
    ) -> Result<(), Self::Error> {
        if let Some(seen) = self.progress_seen.take() {
            let _ = seen.send(());
        }
        if let Some(resume) = self.resume.take() {
            let _ = resume.await;
        }
        Ok(())
    }
}

struct LocalConnection {
    client: russh::client::Handle<LocalClient>,
    channel: Channel<russh::client::Msg>,
    server: tokio::task::JoinHandle<Result<(), SshHandlerError>>,
    release: oneshot::Sender<()>,
    finished: oneshot::Receiver<bool>,
    progress_seen: oneshot::Receiver<()>,
    eof_seen: oneshot::Receiver<()>,
}

async fn local_connection(resume: Option<oneshot::Receiver<()>>) -> LocalConnection {
    let host_key =
        PrivateKey::random(&mut rand010::rng(), russh::keys::Algorithm::Ed25519).unwrap();
    let mut config = ssh_server_config(host_key);
    // Scale only the interval, keeping the production max and inactivity policy.
    config.keepalive_interval = Some(Duration::from_millis(100));
    let (client_stream, server_stream) = tokio::io::duplex(64 * 1024);
    let (release, released) = oneshot::channel();
    let (finished_tx, finished) = oneshot::channel();
    let (progress_tx, progress_seen) = oneshot::channel();
    let (eof_tx, eof_seen) = oneshot::channel();
    let handler = DelayedDeploy {
        gateway: local_server().new_client(None),
        release: Some(released),
        finished: Some(finished_tx),
        eof_seen: Some(eof_tx),
    };
    let server = tokio::spawn(async move {
        russh::server::run_stream(Arc::new(config), server_stream, handler)
            .await?
            .await
    });
    let mut client = russh::client::connect_stream(
        Arc::new(russh::client::Config::default()),
        client_stream,
        LocalClient {
            progress_seen: Some(progress_tx),
            resume,
        },
    )
    .await
    .unwrap();
    assert!(client
        .authenticate_none("local-test")
        .await
        .unwrap()
        .success());
    let channel = client.channel_open_session().await.unwrap();
    channel.exec(false, "delayed-deploy").await.unwrap();
    LocalConnection {
        client,
        channel,
        server,
        release,
        finished,
        progress_seen,
        eof_seen,
    }
}

#[derive(Clone, Default)]
struct LogBuffer(Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for LogBuffer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn capture_session_error(error: SshHandlerError) -> String {
    let buffer = LogBuffer::default();
    let writer = buffer.clone();
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .finish();
    tracing::subscriber::with_default(subscriber, || {
        local_server().handle_session_error(error);
    });
    let bytes = buffer.0.lock().unwrap().clone();
    String::from_utf8(bytes).unwrap()
}

#[tokio::test]
async fn session_errors_are_observable_without_logging_payloads() {
    for (error, category) in [
        (russh::Error::KeepaliveTimeout, "keepalive_timeout"),
        (russh::Error::InactivityTimeout, "inactivity_timeout"),
        (russh::Error::ConnectionTimeout, "connection_timeout"),
        (russh::Error::HUP, "peer_hangup"),
        (russh::Error::Disconnect, "disconnect"),
        (russh::Error::WrongChannel, "wrong_channel"),
        (
            russh::Error::IO(std::io::Error::new(
                std::io::ErrorKind::ConnectionReset,
                "SECRET_transport_payload",
            )),
            "transport_io",
        ),
        (
            russh::Error::InvalidConfig("SECRET_config_payload".into()),
            "protocol",
        ),
    ] {
        let log = capture_session_error(error.into());
        assert!(
            log.contains("SSH session failed"),
            "missing session error event: {log}"
        );
        assert!(
            log.contains(&format!("error_kind=\"{category}\"")),
            "missing safe category: {log}"
        );
        assert!(
            !log.contains("SECRET"),
            "session diagnostics leaked a payload: {log}"
        );
        if category == "transport_io" {
            assert!(
                log.contains("ConnectionReset"),
                "missing safe I/O kind: {log}"
            );
        }
    }
}

#[tokio::test]
async fn responsive_client_survives_silent_deploy_after_channel_eof() {
    tokio::time::timeout(WATCHDOG, async {
        let mut connection = local_connection(None).await;
        connection.progress_seen.await.unwrap();
        connection.channel.data(&b"0000"[..]).await.unwrap();
        connection.channel.eof().await.unwrap();
        connection.eof_seen.await.unwrap();
        tokio::time::sleep(Duration::from_millis(900)).await;
        assert!(
            !connection.server.is_finished(),
            "responsive transport must remain alive beyond the unanswered-keepalive budget"
        );
        connection.release.send(()).unwrap();
        assert!(connection.finished.await.unwrap());
        let mut stderr = Vec::new();
        let mut status = None;
        let mut closed = false;
        while let Some(message) = connection.channel.wait().await {
            match message {
                russh::ChannelMsg::ExtendedData { ext: 1, data } => stderr.extend_from_slice(&data),
                russh::ChannelMsg::ExitStatus { exit_status } => status = Some(exit_status),
                russh::ChannelMsg::Close => {
                    closed = true;
                    break;
                }
                _ => {}
            }
        }
        assert_eq!(stderr, [PROGRESS, COMPLETE].concat());
        assert_eq!(status, Some(0));
        assert!(
            closed,
            "the deploy must close its channel, not the transport"
        );
        connection.client.send_ping().await.unwrap();
        connection
            .client
            .disconnect(russh::Disconnect::ByApplication, "done", "")
            .await
            .unwrap();
        connection.server.await.unwrap().unwrap();
    })
    .await
    .expect("local responsive transport probe timed out");
}

#[tokio::test]
async fn peer_channel_close_during_deploy_does_not_close_transport() {
    tokio::time::timeout(WATCHDOG, async {
        let connection = local_connection(None).await;
        connection.progress_seen.await.unwrap();
        connection.channel.close().await.unwrap();
        connection.client.send_ping().await.unwrap();
        connection.release.send(()).unwrap();
        assert!(
            connection.finished.await.unwrap(),
            "a handle enqueue is not proof that the peer received the data"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
        connection.client.send_ping().await.unwrap();
        assert!(!connection.server.is_finished());
        let another_channel = connection.client.channel_open_session().await.unwrap();
        another_channel.close().await.unwrap();
        connection
            .client
            .disconnect(russh::Disconnect::ByApplication, "done", "")
            .await
            .unwrap();
        connection.server.await.unwrap().unwrap();
    })
    .await
    .expect("local channel-close transport probe timed out");
}

#[tokio::test]
async fn unresponsive_client_times_out_while_detached_deploy_can_finish() {
    tokio::time::timeout(WATCHDOG, async {
        let (resume, paused) = oneshot::channel();
        let connection = local_connection(Some(paused)).await;
        connection.progress_seen.await.unwrap();
        let error = connection.server.await.unwrap().unwrap_err();
        let SshHandlerError::Protocol { source, .. } = &error else {
            panic!("expected a transport timeout");
        };
        assert!(
            matches!(
                source.downcast_ref::<russh::Error>(),
                Some(russh::Error::KeepaliveTimeout)
            ),
            "actual session error: {source:?}"
        );
        let log = capture_session_error(error);
        assert!(
            log.contains("error_kind=\"keepalive_timeout\""),
            "actual timeout must be observable: {log}"
        );
        connection.release.send(()).unwrap();
        assert!(
            !connection.finished.await.unwrap(),
            "the detached task finishes but cannot deliver to the dead transport"
        );
        let _ = resume.send(());
        let _ = connection.client.await;
    })
    .await
    .expect("local unresponsive transport probe timed out");
}
