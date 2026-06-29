//! Direct outbound client.
//!
//! Establishes a direct TCP connection to the destination host without proxying.

use std::io;
use std::time::Duration;

use super::{BackendStream, TargetAddr};

/// Connect directly to a target address (either IP or domain name).
pub async fn direct_connect(
    target: &TargetAddr,
    timeout: Duration,
    bind_interface: Option<&str>,
) -> io::Result<BackendStream> {
    let tcp = match target {
        TargetAddr::Domain(host, port) => {
            super::tcp_connect_raw((host.as_str(), *port), bind_interface, timeout, None)
                .await
                .map_err(|e| {
                    io::Error::new(
                        e.kind(),
                        format!("direct connect to {}:{}: {}", host, port, e),
                    )
                })?
        }
        TargetAddr::Ip(addr) => super::tcp_connect_raw(*addr, bind_interface, timeout, None)
            .await
            .map_err(|e| io::Error::new(e.kind(), format!("direct connect to {}: {}", addr, e)))?,
    };
    tcp.set_nodelay(true)?;
    Ok(BackendStream::tcp(tcp))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn test_direct_connect() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = [0u8; 5];
                if stream.read_exact(&mut buf).await.is_ok() {
                    assert_eq!(&buf, b"hello");
                    let _ = stream.write_all(b"world").await;
                }
            }
        });

        let target = TargetAddr::Domain("127.0.0.1".to_string(), port);
        let mut client = direct_connect(&target, Duration::from_secs(5), None)
            .await
            .unwrap();

        client.write_all(b"hello").await.unwrap();
        let mut resp = [0u8; 5];
        client.read_exact(&mut resp).await.unwrap();
        assert_eq!(&resp, b"world");
    }
}
