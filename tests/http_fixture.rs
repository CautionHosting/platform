// Bounded request-header readers for local HTTP test fixtures.
use dterror::ResultExt;
use std::io::{self, Read};

const MAX_HEADER_BYTES: usize = 16 * 1024;

#[derive(Debug, thiserror::Error, dterror::CtxError)]
pub enum ReadHeadersError {
    #[error("could not read HTTP fixture headers [{location}]")]
    Read {
        #[location]
        location: dterror::Location,
        #[source]
        source: dterror::BoxError,
    },
    #[error("HTTP fixture headers exceed limit [{location}]")]
    TooLarge { location: dterror::Location },
    #[error("HTTP fixture header deadline expired [{location}]")]
    Timeout {
        #[location]
        location: dterror::Location,
        #[source]
        source: dterror::BoxError,
    },
}

pub fn read_headers(reader: &mut impl Read) -> Result<Vec<u8>, ReadHeadersError> {
    let mut headers = Vec::new();
    while headers.len() < MAX_HEADER_BYTES {
        let mut byte = [0];
        reader
            .read_exact(&mut byte)
            .with_context(ReadHeadersErrorCtx::read())?;
        headers.push(byte[0]);
        if headers.ends_with(b"\r\n\r\n") {
            return Ok(headers);
        }
    }
    Err(ReadHeadersError::TooLarge {
        location: std::panic::Location::caller(),
    })
}

pub async fn read_headers_async(
    reader: &mut (impl tokio::io::AsyncRead + Unpin),
) -> Result<Vec<u8>, ReadHeadersError> {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let mut headers = Vec::new();
        while headers.len() < MAX_HEADER_BYTES {
            let mut byte = [0];
            tokio::io::AsyncReadExt::read_exact(reader, &mut byte)
                .await
                .with_context(ReadHeadersErrorCtx::read())?;
            headers.push(byte[0]);
            if headers.ends_with(b"\r\n\r\n") {
                return Ok(headers);
            }
        }
        Err(ReadHeadersError::TooLarge {
            location: std::panic::Location::caller(),
        })
    })
    .await
    .with_context(ReadHeadersErrorCtx::timeout())?
}

#[tokio::test]
async fn async_headers_handle_fragmentation_without_waiting_for_eof() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let headers = b"POST / HTTP/1.1\r\nContent-Length: 2\r\n\r\n";
    let (mut client, mut server) = tokio::io::duplex(1);
    let (done, wait) = tokio::sync::oneshot::channel();
    let writer = tokio::spawn(async move {
        client.write_all(headers).await.unwrap();
        client.write_all(b"{}").await.unwrap();
        wait.await.unwrap();
    });
    assert_eq!(read_headers_async(&mut server).await.unwrap(), headers);
    let mut body = [0; 2];
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        server.read_exact(&mut body),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(&body, b"{}");
    done.send(()).unwrap();
    writer.await.unwrap();
}

#[tokio::test]
async fn async_headers_reject_eof_and_oversized_headers() {
    let headers = b"GET / HTTP/1.1\r\n\r\n";
    for end in 0..headers.len() {
        assert!(
            matches!(
                read_headers_async(&mut &headers[..end]).await,
                Err(ReadHeadersError::Read { source, .. })
                    if source.downcast_ref::<io::Error>().unwrap().kind() == io::ErrorKind::UnexpectedEof
            ),
            "EOF at {end}"
        );
    }
    assert!(matches!(
        read_headers_async(&mut vec![b'x'; MAX_HEADER_BYTES].as_slice()).await,
        Err(ReadHeadersError::TooLarge { .. })
    ));
}

#[test]
fn sync_headers_handle_fragmentation_without_consuming_the_body() {
    let headers = b"POST / HTTP/1.1\r\nContent-Length: 2\r\n\r\n";
    for split in 1..headers.len() {
        let rest = [headers[split..].to_vec(), b"{}".to_vec()].concat();
        let mut input = headers[..split].chain(rest.as_slice());
        assert_eq!(read_headers(&mut input).unwrap(), headers, "split {split}");
        let mut body = [0; 2];
        input.read_exact(&mut body).unwrap();
        assert_eq!(&body, b"{}");
    }
}

#[test]
fn sync_headers_reject_eof_and_oversized_headers() {
    let headers = b"GET / HTTP/1.1\r\n\r\n";
    for end in 0..headers.len() {
        assert!(
            matches!(
                read_headers(&mut &headers[..end]),
                Err(ReadHeadersError::Read { source, .. })
                    if source.downcast_ref::<io::Error>().unwrap().kind() == io::ErrorKind::UnexpectedEof
            ),
            "EOF at {end}"
        );
    }
    assert!(matches!(
        read_headers(&mut vec![b'x'; MAX_HEADER_BYTES].as_slice()),
        Err(ReadHeadersError::TooLarge { .. })
    ));
}
