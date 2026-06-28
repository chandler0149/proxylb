use std::env;
use std::path::Path;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;
use tokio::time::timeout;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let socket_path = if args.len() > 1 {
        &args[1]
    } else {
        "/tmp/mock_socks5.sock"
    };

    let path = Path::new(socket_path);
    if path.exists() {
        let _ = std::fs::remove_file(path);
    }

    let listener = std::sync::Arc::new(UnixListener::bind(path)?);
    println!(
        "Mock Rust UDS SOCKS5 backend running on {} with 16 parallel acceptors",
        socket_path
    );

    let mut acceptor_handles = Vec::new();

    // Spawn 16 parallel acceptor tasks to aggressively drain the OS connection backlog
    for _i in 0..16 {
        let listener = std::sync::Arc::clone(&listener);
        let handle = tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((mut stream, _)) => {
                        // Offload handling to a fast background task
                        tokio::spawn(async move {
                            let mut buf = [0u8; 1024];

                            // 1. Read greeting
                            match stream.read(&mut buf).await {
                                Ok(n) if n >= 2 && buf[0] == 0x05 => {
                                    if stream.write_all(&[0x05, 0x00]).await.is_err() {
                                        return;
                                    }
                                }
                                _ => return, // Silent drop on malformed requests for speed
                            }

                            // 2. Read CONNECT request
                            match stream.read(&mut buf).await {
                                Ok(n) if n >= 4 && buf[1] == 0x01 => {
                                    // Respond success
                                    let resp = [0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
                                    if stream.write_all(&resp).await.is_err() {
                                        return;
                                    }
                                }
                                _ => return,
                            }

                            // 3. Handle data or health check (fast exit)
                            let mut req_buf = [0u8; 256];
                            if let Ok(Ok(n)) =
                                timeout(Duration::from_millis(10), stream.read(&mut req_buf)).await
                            {
                                if n > 0 && req_buf.starts_with(b"GET") {
                                    let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK").await;
                                }
                            }
                        });
                    }
                    Err(_e) => {
                        // Log only occasionally or silently ignore typical UDS accept errors like EAGAIN
                        // eprintln!("Acceptor {} error: {}", i, e);
                    }
                }
            }
        });
        acceptor_handles.push(handle);
    }

    // Wait forever
    for handle in acceptor_handles {
        let _ = handle.await;
    }

    Ok(())
}
