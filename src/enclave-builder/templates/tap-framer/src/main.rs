//! Linux TAP/vsock tunnel: u32 big-endian length, then one Ethernet frame.
//! The 1500-byte MTU allows Ethernet frames of 14..=1518 bytes (one VLAN tag).
//! No packet-info or virtio headers/offloads are enabled; addressing/routing are external.

mod vsock;

use std::error::Error;
use std::ffi::{OsStr, OsString};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::sync::mpsc;
use std::thread;

use dterror::{BoxError, CtxError, Location, ResultExt};

const MIN_FRAME: usize = 14;
const MAX_FRAME: usize = 1518;

#[derive(Debug, thiserror::Error, CtxError)]
enum FramingError {
    #[error("usage: tap-framer <tap-name> | --connect <cid> <port> <tap-name> | --listen <port> <tap-name> [{location}]")]
    Usage { location: Location },
    #[error("TAP name must contain 1..IFNAMSIZ bytes without NUL [{location}]")]
    InvalidTapName { location: Location },
    #[error("invalid Ethernet frame length {length}; expected 14..=1518 [{location}]")]
    InvalidLength { length: usize, location: Location },
    #[error("short TAP write: wrote {written} of {length} bytes [{location}]")]
    ShortTapWrite {
        written: usize,
        length: usize,
        location: Location,
    },
    #[error("could not {operation} [{location}]")]
    Io {
        operation: &'static str,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

#[tracing::instrument(skip_all, err)]
fn validate_length(length: usize) -> Result<(), FramingError> {
    if !(MIN_FRAME..=MAX_FRAME).contains(&length) {
        return Err(FramingError::InvalidLength {
            length,
            location: std::panic::Location::caller(),
        });
    }
    Ok(())
}

#[tracing::instrument(skip_all, err)]
fn retry_io<T>(
    operation: &'static str,
    mut action: impl FnMut() -> io::Result<T>,
) -> Result<T, FramingError> {
    use FramingErrorCtx as Ctx;
    loop {
        match action() {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            result => return result.with_context(Ctx::io(operation)),
        }
    }
}

/// A successful TAP write is exactly one frame, never a write_all remainder.
#[tracing::instrument(skip_all, err)]
fn stream_to_tap(mut stream: impl Read, mut tap: impl Write) -> Result<(), FramingError> {
    use FramingErrorCtx as Ctx;
    let mut frame = [0; MAX_FRAME];
    loop {
        let mut header = [0; 4];
        if retry_io("read frame header", || stream.read(&mut header[..1]))? == 0 {
            return Ok(());
        }
        stream
            .read_exact(&mut header[1..])
            .with_context(Ctx::io("read frame header"))?;
        let length = u32::from_be_bytes(header) as usize;
        validate_length(length)?;
        stream
            .read_exact(&mut frame[..length])
            .with_context(Ctx::io("read frame body"))?;
        let written = retry_io("write TAP frame", || tap.write(&frame[..length]))?;
        if written != length {
            return Err(FramingError::ShortTapWrite {
                written,
                length,
                location: std::panic::Location::caller(),
            });
        }
    }
}

/// The extra read byte detects oversize frames that TAP would otherwise truncate.
#[tracing::instrument(skip_all, err)]
fn tap_to_stream(mut tap: impl Read, mut stream: impl Write) -> Result<(), FramingError> {
    use FramingErrorCtx as Ctx;
    let mut frame = [0; MAX_FRAME + 1];
    loop {
        let length = retry_io("read TAP frame", || tap.read(&mut frame))?;
        if length == 0 {
            return Ok(());
        }
        validate_length(length)?;
        stream
            .write_all(&(length as u32).to_be_bytes())
            .with_context(Ctx::io("write frame header"))?;
        stream
            .write_all(&frame[..length])
            .with_context(Ctx::io("write frame body"))?;
        retry_io("flush frame", || stream.flush())?;
    }
}

#[tracing::instrument(skip_all, err)]
fn tap_request(name: &OsStr) -> Result<libc::ifreq, FramingError> {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.len() >= libc::IFNAMSIZ || bytes.contains(&0) {
        return Err(FramingError::InvalidTapName {
            location: std::panic::Location::caller(),
        });
    }
    // SAFETY: Linux ifreq contains integer, byte-array and raw-pointer fields;
    // all-zero bytes are a valid initial value for each of them.
    let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
    for (destination, source) in request.ifr_name.iter_mut().zip(bytes) {
        *destination = *source as libc::c_char;
    }
    request.ifr_ifru.ifru_flags = (libc::IFF_TAP | libc::IFF_NO_PI) as libc::c_short;
    Ok(request)
}

#[tracing::instrument(skip_all, err)]
fn open_tap(name: &OsStr) -> Result<File, FramingError> {
    let mut request = tap_request(name)?;
    let tap = retry_io("open /dev/net/tun", || {
        OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/net/tun")
    })?;
    retry_io("attach TAP with TUNSETIFF", || {
        // SAFETY: tap owns an open TUN descriptor; request is a valid, writable
        // Linux ifreq with a NUL-terminated name and TAP flags for TUNSETIFF.
        let result = unsafe { libc::ioctl(tap.as_raw_fd(), libc::TUNSETIFF, &mut request) };
        if result < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    })?;
    // A peer may already have queued frames. TAP rejects writes while DOWN, so
    // bring the link UP before either forwarding worker can run.
    let control_fd = retry_io("create TAP link control socket", || {
        // SAFETY: socket takes integer constants and returns a new owned descriptor.
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
        if fd < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(fd)
        }
    })?;
    // SAFETY: control_fd is a newly created, valid descriptor with no other owner.
    let control = unsafe { File::from_raw_fd(control_fd) };
    retry_io("read TAP link flags", || {
        // SAFETY: control owns a socket and request names the attached TAP interface;
        // SIOCGIFFLAGS initializes ifru_flags on success. Cast the request for
        // musl's int versus glibc's unsigned-long ioctl ABI.
        let result =
            unsafe { libc::ioctl(control.as_raw_fd(), libc::SIOCGIFFLAGS as _, &mut request) };
        if result < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    })?;
    // SAFETY: SIOCGIFFLAGS successfully initialized ifru_flags above.
    request.ifr_ifru.ifru_flags =
        unsafe { request.ifr_ifru.ifru_flags } | libc::IFF_UP as libc::c_short;
    retry_io("bring TAP link up", || {
        // SAFETY: control owns a socket and request contains the TAP name and
        // its existing link flags with IFF_UP added.
        let result = unsafe { libc::ioctl(control.as_raw_fd(), libc::SIOCSIFFLAGS as _, &request) };
        if result < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    })?;
    Ok(tap)
}

/// Returns the first completion; main exits the process to stop the other worker.
#[tracing::instrument(skip_all, err)]
fn relay(
    inbound: impl FnOnce() -> Result<(), FramingError> + Send + 'static,
    outbound: impl FnOnce() -> Result<(), FramingError> + Send + 'static,
) -> Result<(), FramingError> {
    use FramingErrorCtx as Ctx;
    let (sender, receiver) = mpsc::channel();
    let inbound_sender = sender.clone();
    thread::Builder::new()
        .name("stdin-to-tap".into())
        .spawn(move || {
            let _ = inbound_sender.send(inbound());
        })
        .with_context(Ctx::io("spawn stdin-to-TAP worker"))?;
    thread::Builder::new()
        .name("tap-to-stdout".into())
        .spawn(move || {
            let _ = sender.send(outbound());
        })
        .with_context(Ctx::io("spawn TAP-to-stdout worker"))?;
    receiver
        .recv()
        .with_context(Ctx::io("receive worker completion"))?
}

#[tracing::instrument(skip_all, err)]
fn endpoint_number(value: &OsStr) -> Result<u32, FramingError> {
    value
        .to_str()
        .ok_or_else(|| FramingError::Usage {
            location: std::panic::Location::caller(),
        })?
        .parse()
        .with_context(FramingErrorCtx::io("parse vsock endpoint"))
}

#[tracing::instrument(skip_all, err)]
fn run(arguments: impl Iterator<Item = OsString>) -> Result<(), FramingError> {
    use FramingErrorCtx as Ctx;
    let arguments: Vec<_> = arguments.collect();
    let (name, input, output) = match arguments.as_slice() {
        [name] => {
            tap_request(name)?;
            let input = File::from(retry_io("clone stdin descriptor", || {
                io::stdin().as_fd().try_clone_to_owned()
            })?);
            let output = File::from(retry_io("clone stdout descriptor", || {
                io::stdout().as_fd().try_clone_to_owned()
            })?);
            (name, input, output)
        }
        [flag, port, name] if flag == "--listen" => {
            tap_request(name)?;
            return vsock::serve(endpoint_number(port)?, name)
                .with_context(Ctx::io("serve vsock tunnel"));
        }
        [flag, cid, port, name] if flag == "--connect" => {
            tap_request(name)?;
            let input = vsock::connect(endpoint_number(cid)?, endpoint_number(port)?)
                .with_context(Ctx::io("connect vsock tunnel"))?;
            let output = retry_io("clone vsock descriptor", || input.try_clone())?;
            (name, input, output)
        }
        _ => {
            return Err(FramingError::Usage {
                location: std::panic::Location::caller(),
            })
        }
    };
    let tap = open_tap(name)?;
    let tap_writer = retry_io("clone TAP descriptor", || tap.try_clone())?;
    relay(
        move || stream_to_tap(input, tap_writer),
        move || tap_to_stream(tap, output),
    )
}

#[tracing::instrument(skip_all)]
fn main() {
    let status = match run(std::env::args_os().skip(1)) {
        Ok(()) => 0,
        Err(error) => {
            let mut stderr = io::stderr().lock();
            let _ = writeln!(stderr, "tap-framer: {error}");
            let mut source = error.source();
            while let Some(cause) = source {
                let _ = writeln!(stderr, "  caused by: {cause}");
                source = cause.source();
            }
            1
        }
    };
    std::process::exit(status);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    #[test]
    fn invalid_native_endpoints_preserve_parse_error_context() {
        for arguments in [
            vec!["--connect", "bad-cid", "3", "tap0"],
            vec!["--connect", "3", "bad-port", "tap0"],
            vec!["--listen", "bad-port", "tap0"],
        ] {
            let FramingError::Io {
                operation, source, ..
            } = run(arguments.into_iter().map(OsString::from))
                .expect_err("invalid native endpoint")
            else {
                panic!("invalid endpoint must preserve its parse error");
            };
            assert_eq!(operation, "parse vsock endpoint");
            assert!(source.is::<std::num::ParseIntError>());
        }
    }

    #[test]
    fn cli_requires_exactly_one_tap_name_before_opening_any_device() {
        for arguments in [vec![], vec!["tap0", "extra"]] {
            let error = run(arguments.into_iter().map(OsString::from))
                .expect_err("missing or extra argument");
            assert!(matches!(error, FramingError::Usage { .. }));
        }
        assert!(matches!(
            run([OsString::new()].into_iter()),
            Err(FramingError::InvalidTapName { .. })
        ));
    }

    #[test]
    fn first_direction_to_finish_returns_without_waiting_for_blocked_peer() {
        use std::time::Duration;
        for finish_outbound in [false, true] {
            for fail in [false, true] {
                let (release, blocked) = mpsc::channel();
                let (done, result) = mpsc::channel();
                let coordinator = thread::spawn(move || {
                    let finish = move || {
                        if fail {
                            validate_length(0)
                        } else {
                            Ok(())
                        }
                    };
                    let wait = move || {
                        let _ = blocked.recv();
                        Ok(())
                    };
                    let outcome = if finish_outbound {
                        relay(wait, finish)
                    } else {
                        relay(finish, wait)
                    };
                    done.send(outcome).expect("report completion");
                });
                let outcome = result.recv_timeout(Duration::from_secs(2));
                let _ = release.send(());
                coordinator.join().expect("coordinator must not panic");
                let outcome = outcome.expect("first completion must not wait for blocked peer");
                if fail {
                    assert!(matches!(
                        outcome,
                        Err(FramingError::InvalidLength { length: 0, .. })
                    ));
                } else {
                    outcome.expect("clean completion");
                }
            }
        }
    }

    #[test]
    #[ignore = "requires CAP_NET_ADMIN and ip in an isolated network namespace"]
    fn real_tap_is_up_and_lives_until_last_owned_fd_closes() {
        let name = "framer-test0";
        let tap = open_tap(OsStr::new(name)).expect("open real TAP");
        let clone = tap.try_clone().expect("clone TAP descriptor");
        drop(tap);
        let output = std::process::Command::new("ip")
            .args(["link", "show", "dev", name])
            .output()
            .expect("inspect interface");
        assert!(
            output.status.success(),
            "TAP exists while its clone is owned: {output:?}"
        );
        let description = String::from_utf8_lossy(&output.stdout);
        assert!(
            description.contains(",UP,"),
            "TAP must be UP before forwarding starts: {description}"
        );
        assert!(description.contains("mtu 1500"));
        assert!(description.contains("link/ether"));
        drop(clone);
        let output = std::process::Command::new("ip")
            .args(["link", "show", "dev", name])
            .output()
            .expect("inspect removed interface");
        assert!(!output.status.success(), "TAP is not made persistent");
    }

    #[test]
    fn tap_request_uses_exact_name_and_only_tap_no_pi_flags() {
        let request = tap_request(OsStr::new("enclave-tap0")).expect("valid name");
        let name: Vec<u8> = request.ifr_name.iter().map(|byte| *byte as u8).collect();
        let expected = b"enclave-tap0\0";
        assert_eq!(&name[..expected.len()], expected);
        assert!(name[expected.len()..].iter().all(|byte| *byte == 0));
        // SAFETY: tap_request initializes the ifru_flags member for TUNSETIFF.
        let flags = unsafe { request.ifr_ifru.ifru_flags };
        assert_eq!(flags as i32, libc::IFF_TAP | libc::IFF_NO_PI);
    }

    #[test]
    fn tap_name_must_be_nonempty_nul_free_and_fit_ifnamsiz() {
        for name in [b"".as_slice(), b"tap\0bad", b"1234567890123456"] {
            assert!(
                matches!(
                    tap_request(OsStr::from_bytes(name)),
                    Err(FramingError::InvalidTapName { .. })
                ),
                "invalid name {name:?}"
            );
        }
        assert!(tap_request(OsStr::new("123456789012345")).is_ok());
        assert!(
            tap_request(OsStr::from_bytes(&[0xff; 15])).is_ok(),
            "Linux names are bytes, not necessarily UTF-8"
        );
    }

    struct Chunked<'a> {
        bytes: &'a [u8],
        chunk_size: usize,
    }

    impl Read for Chunked<'_> {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            let length = output.len().min(self.chunk_size).min(self.bytes.len());
            output[..length].copy_from_slice(&self.bytes[..length]);
            self.bytes = &self.bytes[length..];
            Ok(length)
        }
    }

    #[derive(Default)]
    struct PacketSink(Vec<Vec<u8>>);

    impl Write for PacketSink {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.push(bytes.to_vec());
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn wire(frames: &[Vec<u8>]) -> Vec<u8> {
        frames
            .iter()
            .flat_map(|frame| {
                (frame.len() as u32)
                    .to_be_bytes()
                    .into_iter()
                    .chain(frame.iter().copied())
            })
            .collect()
    }

    struct Interrupted<T> {
        inner: T,
        interrupt: bool,
    }

    impl<T: Read> Read for Interrupted<T> {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            self.interrupt = !self.interrupt;
            if self.interrupt {
                Err(io::ErrorKind::Interrupted.into())
            } else {
                self.inner.read(bytes)
            }
        }
    }

    impl<T: Write> Write for Interrupted<T> {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.interrupt = !self.interrupt;
            if self.interrupt {
                Err(io::ErrorKind::Interrupted.into())
            } else {
                self.inner.write(bytes)
            }
        }

        fn flush(&mut self) -> io::Result<()> {
            self.interrupt = !self.interrupt;
            if self.interrupt {
                Err(io::ErrorKind::Interrupted.into())
            } else {
                self.inner.flush()
            }
        }
    }

    #[test]
    fn interrupted_stream_reads_and_tap_writes_retry_without_packet_duplication() {
        let frames = vec![vec![0x12; 14], vec![0x34; 60]];
        let encoded = wire(&frames);
        let stream = Interrupted {
            inner: Chunked {
                bytes: &encoded,
                chunk_size: 2,
            },
            interrupt: false,
        };
        let mut tap = Interrupted {
            inner: PacketSink::default(),
            interrupt: false,
        };
        stream_to_tap(stream, &mut tap).expect("EINTR is retried");
        assert_eq!(tap.inner.0, frames);
    }

    struct PacketSource(std::vec::IntoIter<Vec<u8>>);

    impl Read for PacketSource {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            match self.0.next() {
                Some(frame) => {
                    let length = bytes.len().min(frame.len());
                    bytes[..length].copy_from_slice(&frame[..length]);
                    Ok(length)
                }
                None => Ok(0),
            }
        }
    }

    #[derive(Default)]
    struct PartialStream {
        bytes: Vec<u8>,
        flushed_lengths: Vec<usize>,
    }

    impl Write for PartialStream {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            let length = bytes.len().min(3);
            self.bytes.extend_from_slice(&bytes[..length]);
            Ok(length)
        }

        fn flush(&mut self) -> io::Result<()> {
            self.flushed_lengths.push(self.bytes.len());
            Ok(())
        }
    }

    #[test]
    fn tap_packets_become_flushed_records_despite_partial_and_interrupted_io() {
        let frames = vec![vec![0x12; 14], vec![0x34; 60], vec![0x56; 1518]];
        let tap = Interrupted {
            inner: PacketSource(frames.clone().into_iter()),
            interrupt: false,
        };
        let mut stream = Interrupted {
            inner: PartialStream::default(),
            interrupt: false,
        };
        tap_to_stream(tap, &mut stream).expect("EINTR and partial stream writes are retried");
        assert!(
            stream.inner.bytes == wire(&frames),
            "wire bytes include u32 BE lengths"
        );
        assert_eq!(stream.inner.flushed_lengths, [18, 82, 1604]);
    }

    #[test]
    fn oversized_tap_packet_is_rejected_instead_of_silently_truncated() {
        for length in [1519, 65536] {
            let mut stream = Vec::new();
            let tap = PacketSource(vec![vec![0x12; length]].into_iter());
            let error = tap_to_stream(tap, &mut stream).expect_err("oversized TAP packet");
            assert!(matches!(
                error,
                FramingError::InvalidLength { length: 1519, .. }
            ));
            assert!(
                stream.is_empty(),
                "truncated data must never reach the wire"
            );
        }
    }

    #[test]
    fn undersized_tap_packet_is_rejected() {
        let mut stream = Vec::new();
        let tap = PacketSource(vec![vec![0x12; 13]].into_iter());
        assert!(matches!(
            tap_to_stream(tap, &mut stream),
            Err(FramingError::InvalidLength { length: 13, .. })
        ));
        assert!(stream.is_empty());
    }

    struct ShortWriter {
        written: usize,
        calls: usize,
    }

    impl Write for ShortWriter {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            self.calls += 1;
            Ok(self.written)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn short_tap_write_is_fatal_without_writing_the_remainder() {
        let encoded = wire(&[vec![0x12; 14]]);
        for written in [0, 1, 13] {
            let mut tap = ShortWriter { written, calls: 0 };
            let error =
                stream_to_tap(encoded.as_slice(), &mut tap).expect_err("short TAP write must fail");
            assert!(
                matches!(error, FramingError::ShortTapWrite { written: actual, length: 14, .. } if actual == written)
            );
            assert_eq!(tap.calls, 1, "remainder is not another packet");
        }
    }

    #[test]
    fn eof_is_clean_only_between_records() {
        let encoded = wire(&[vec![0x12; 14]]);
        for end in 0..=encoded.len() {
            let mut tap = PacketSink::default();
            let result = stream_to_tap(&encoded[..end], &mut tap);
            if end == 0 || end == encoded.len() {
                result.expect("EOF at a record boundary is clean");
            } else {
                let FramingError::Io {
                    operation, source, ..
                } = result.expect_err("truncated record")
                else {
                    panic!("truncated record should preserve its I/O source");
                };
                assert_eq!(
                    operation,
                    if end < 4 {
                        "read frame header"
                    } else {
                        "read frame body"
                    }
                );
                assert_eq!(
                    source
                        .downcast_ref::<io::Error>()
                        .expect("I/O source")
                        .kind(),
                    io::ErrorKind::UnexpectedEof
                );
                assert!(tap.0.is_empty(), "no partial packet is delivered");
            }
        }
    }

    #[test]
    fn invalid_wire_lengths_are_rejected_before_reading_a_body() {
        for length in [0_u32, 1, 13, 1519, u32::MAX] {
            let mut tap = PacketSink::default();
            let header = length.to_be_bytes();
            let error = stream_to_tap(header.as_slice(), &mut tap)
                .expect_err("invalid length must fail before reading any body");
            assert!(
                matches!(error, FramingError::InvalidLength { length: actual, .. } if actual == length as usize)
            );
            assert!(tap.0.is_empty(), "invalid records must never reach TAP");
        }
    }

    struct FailingIo;

    impl Read for FailingIo {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::ErrorKind::ConnectionReset.into())
        }
    }

    impl Write for FailingIo {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::ErrorKind::BrokenPipe.into())
        }

        fn flush(&mut self) -> io::Result<()> {
            Err(io::ErrorKind::BrokenPipe.into())
        }
    }

    #[test]
    fn io_failures_keep_their_operation_and_source() {
        let encoded = wire(&[vec![0x12; 14]]);
        let cases = [
            (
                stream_to_tap(FailingIo, io::sink()),
                "read frame header",
                io::ErrorKind::ConnectionReset,
            ),
            (
                stream_to_tap(encoded.as_slice(), FailingIo),
                "write TAP frame",
                io::ErrorKind::BrokenPipe,
            ),
            (
                tap_to_stream(FailingIo, io::sink()),
                "read TAP frame",
                io::ErrorKind::ConnectionReset,
            ),
            (
                tap_to_stream(PacketSource(vec![vec![0x12; 14]].into_iter()), FailingIo),
                "write frame header",
                io::ErrorKind::BrokenPipe,
            ),
            (
                retry_io("flush frame", || FailingIo.flush()),
                "flush frame",
                io::ErrorKind::BrokenPipe,
            ),
        ];
        for (result, expected_operation, expected_kind) in cases {
            let FramingError::Io {
                operation, source, ..
            } = result.expect_err("I/O must fail")
            else {
                panic!("I/O source must be preserved");
            };
            assert_eq!(operation, expected_operation);
            assert_eq!(
                source
                    .downcast_ref::<io::Error>()
                    .expect("I/O source")
                    .kind(),
                expected_kind
            );
        }
    }

    #[test]
    fn zero_stream_write_is_fatal_instead_of_spinning() {
        let tap = PacketSource(vec![vec![0x12; 14]].into_iter());
        let mut stream = ShortWriter {
            written: 0,
            calls: 0,
        };
        let FramingError::Io { source, .. } =
            tap_to_stream(tap, &mut stream).expect_err("zero stream write")
        else {
            panic!("zero write must preserve I/O source");
        };
        assert_eq!(
            source
                .downcast_ref::<io::Error>()
                .expect("I/O source")
                .kind(),
            io::ErrorKind::WriteZero
        );
        assert_eq!(stream.calls, 1);
    }

    #[test]
    fn eof_after_complete_packet_and_partial_next_packet_never_writes_partial_tap() {
        let first = vec![0x12; 14];
        let second = wire(&[vec![0x34; 60]]);
        for end in 1..second.len() {
            let mut encoded = wire(std::slice::from_ref(&first));
            encoded.extend_from_slice(&second[..end]);
            let mut tap = PacketSink::default();
            assert!(stream_to_tap(encoded.as_slice(), &mut tap).is_err());
            assert_eq!(tap.0.as_slice(), std::slice::from_ref(&first));
        }
    }

    #[test]
    fn split_and_coalesced_stream_preserves_packet_boundaries() {
        let frames = vec![vec![0x12; 14], vec![0x34; 60], vec![0x56; 1518]];
        let encoded = wire(&frames);
        for chunk_size in [1, 2, 3, 4, 7, 19, 1518, encoded.len()] {
            let mut tap = PacketSink::default();
            stream_to_tap(
                Chunked {
                    bytes: &encoded,
                    chunk_size,
                },
                &mut tap,
            )
            .expect("valid framed stream");
            assert_eq!(tap.0, frames, "stream chunk size {chunk_size}");
        }
    }
}
