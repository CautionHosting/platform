//! Native Linux vsock transport; accepted sockets become the helper child's stdio.

use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::process::{Command, Stdio};

use dterror::{BoxError, CtxError, Location, ResultExt};

/// A socket or child-process operation failed.
#[derive(Debug, thiserror::Error, CtxError)]
#[error("could not {operation} [{location}]")]
pub(crate) struct VsockError {
    operation: &'static str,
    #[location]
    location: Location,
    #[source]
    source: BoxError,
}

#[tracing::instrument(skip_all, err)]
fn syscall(
    operation: &'static str,
    action: impl FnOnce() -> libc::c_int,
) -> Result<libc::c_int, VsockError> {
    use VsockErrorCtx as Ctx;
    let result = action();
    if result < 0 {
        Err(io::Error::last_os_error()).with_context(Ctx::new(operation))
    } else {
        Ok(result)
    }
}

#[tracing::instrument(skip_all)]
fn address(cid: u32, port: u32) -> libc::sockaddr_vm {
    // SAFETY: sockaddr_vm contains only integer and byte-array fields, for which
    // zero is valid; the reserved fields must remain zero for the Linux ABI.
    let mut address: libc::sockaddr_vm = unsafe { std::mem::zeroed() };
    address.svm_family = libc::AF_VSOCK as libc::sa_family_t;
    address.svm_cid = cid;
    address.svm_port = port;
    address
}

#[tracing::instrument(skip_all, err)]
fn socket() -> Result<File, VsockError> {
    // SAFETY: socket takes integer constants and returns a new owned descriptor.
    let fd = syscall("create vsock socket", || unsafe {
        libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0)
    })?;
    // SAFETY: fd is a newly created, valid descriptor with no other Rust owner.
    Ok(unsafe { File::from_raw_fd(fd) })
}

/// Connect to a vsock stream without introducing a userspace copying relay.
#[tracing::instrument(skip_all, err)]
pub(crate) fn connect(cid: u32, port: u32) -> Result<File, VsockError> {
    let stream = socket()?;
    let address = address(cid, port);
    // SAFETY: stream owns the socket; address is initialized and its pointer and
    // length describe a sockaddr_vm that remains live throughout connect.
    syscall("connect vsock socket", || unsafe {
        libc::connect(
            stream.as_raw_fd(),
            (&address as *const libc::sockaddr_vm).cast(),
            std::mem::size_of_val(&address) as libc::socklen_t,
        )
    })?;
    Ok(stream)
}

#[tracing::instrument(skip_all, err)]
fn accept(listener: &File) -> Result<File, VsockError> {
    use VsockErrorCtx as Ctx;
    loop {
        // SAFETY: listener owns a live descriptor; null address pointers request
        // no peer address, and accept4 returns a new owned descriptor on success.
        let fd = unsafe {
            libc::accept4(
                listener.as_raw_fd(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                libc::SOCK_CLOEXEC,
            )
        };
        if fd >= 0 {
            // SAFETY: accept4 returned a valid descriptor with no other owner.
            return Ok(unsafe { File::from_raw_fd(fd) });
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error).with_context(Ctx::new("accept vsock connection"));
        }
    }
}

/// Serve one child at a time so only one process can own the TAP interface.
#[tracing::instrument(skip_all, err)]
pub(crate) fn serve(port: u32, tap_name: &OsStr) -> Result<(), VsockError> {
    use VsockErrorCtx as Ctx;
    let executable =
        std::env::current_exe().with_context(Ctx::new("locate tap-framer executable"))?;
    let listener = socket()?;
    let address = address(libc::VMADDR_CID_ANY, port);
    // SAFETY: listener owns the socket; address is initialized and its pointer
    // and length describe a sockaddr_vm that remains live throughout bind.
    syscall("bind vsock listener", || unsafe {
        libc::bind(
            listener.as_raw_fd(),
            (&address as *const libc::sockaddr_vm).cast(),
            std::mem::size_of_val(&address) as libc::socklen_t,
        )
    })?;
    // SAFETY: listener owns a live socket descriptor and the backlog is positive.
    syscall("listen on vsock socket", || unsafe {
        libc::listen(listener.as_raw_fd(), 16)
    })?;
    loop {
        let stream = accept(&listener)?;
        let input = stream
            .try_clone()
            .with_context(Ctx::new("clone accepted vsock socket"))?;
        let mut child = Command::new(&executable)
            .arg(tap_name)
            .stdin(Stdio::from(input))
            .stdout(Stdio::from(stream))
            .stderr(Stdio::inherit())
            .spawn()
            .with_context(Ctx::new("spawn TAP connection helper"))?;
        let status = child
            .wait()
            .with_context(Ctx::new("wait for TAP connection helper"))?;
        if !status.success() {
            let _ = writeln!(
                io::stderr().lock(),
                "tap-framer: connection helper exited with {status}"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_sets_host_order_fields_and_zeroes_reserved_fields() {
        for (cid, port) in [(3, 1024), (libc::VMADDR_CID_ANY, u32::MAX)] {
            let address = address(cid, port);
            assert_eq!(address.svm_family, libc::AF_VSOCK as libc::sa_family_t);
            assert_eq!(address.svm_cid, cid);
            assert_eq!(address.svm_port, port);
            assert_eq!(address.svm_reserved1, 0);
            assert!(address.svm_zero.iter().all(|byte| *byte == 0));
        }
    }

    #[test]
    fn accept_preserves_non_socket_os_error_and_context() {
        let file = File::open("/dev/null").expect("open non-socket descriptor");
        let error = accept(&file).expect_err("cannot accept on /dev/null");
        assert_eq!(error.operation, "accept vsock connection");
        let source = error
            .source
            .downcast_ref::<io::Error>()
            .expect("OS error source");
        assert_eq!(source.raw_os_error(), Some(libc::ENOTSOCK));
        assert!(error.location.file().ends_with("vsock.rs"));
    }
}
