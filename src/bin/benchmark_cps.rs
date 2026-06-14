//! SOCKS5 Connections-Per-Second benchmarker.
//!
//! Measures how many SOCKS5 CONNECT round-trips per second ProxyLB can handle.
//!
//! On macOS the default ephemeral port range (~16 k ports) combined with
//! TIME_WAIT (~60 s) causes EADDRNOTAVAIL under sustained high-CPS load.
//! This tool works around the limit in two ways:
//!   1. SO_REUSEADDR + SO_REUSEPORT on every outbound socket so the kernel
//!      reuses TIME_WAIT ports immediately.
//!   2. --proxy-uds <path> flag: connect to the proxy over a Unix-domain
//!      socket instead of TCP, which has no port-space at all.

use clap::Parser;
use std::net::{Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Parser, Debug)]
#[command(name = "benchmark_cps", about = "SOCKS5 CPS Benchmarker in Rust")]
struct Args {
    #[arg(long, default_value = "127.0.0.1")]
    proxy_host: String,

    #[arg(long, default_value = "1080")]
    proxy_port: u16,

    /// Optional: connect to the proxy via a Unix-domain socket path
    /// (e.g. /tmp/proxylb_bench.sock). Avoids TCP port exhaustion on macOS.
    #[arg(long)]
    proxy_uds: Option<String>,

    #[arg(long, default_value = "127.0.0.1")]
    target_host: String,

    #[arg(long, default_value = "10800")]
    target_port: u16,

    #[arg(long, default_value = "300")]
    concurrency: usize,

    #[arg(long, default_value = "10")]
    duration: u64,
}

// ─── TCP path ────────────────────────────────────────────────────────────────

async fn test_socks5_tcp(
    proxy_addr: SocketAddr,
    target_ip_bytes: [u8; 4],
    target_port_bytes: [u8; 2],
) -> bool {
    // Use TcpSocket so we can set SO_REUSEADDR + SO_REUSEPORT before connect.
    // This lets the kernel reuse ports that are still in TIME_WAIT, preventing
    // EADDRNOTAVAIL (os error 49) on macOS under high connection rates.
    let socket = match tokio::net::TcpSocket::new_v4() {
        Ok(s) => s,
        Err(_) => return false,
    };
    let _ = socket.set_reuseaddr(true);
    #[cfg(unix)]
    let _ = socket.set_reuseport(true);

    let mut stream = match socket.connect(proxy_addr).await {
        Ok(s) => s,
        Err(_) => return false,
    };
    let _ = stream.set_nodelay(true);

    do_socks5_handshake(&mut stream, &target_ip_bytes, &target_port_bytes).await
}

// ─── UDS path ────────────────────────────────────────────────────────────────

async fn test_socks5_uds(
    proxy_path: &str,
    target_ip_bytes: [u8; 4],
    target_port_bytes: [u8; 2],
) -> bool {
    let mut stream = match tokio::net::UnixStream::connect(proxy_path).await {
        Ok(s) => s,
        Err(_) => return false,
    };
    do_socks5_handshake(&mut stream, &target_ip_bytes, &target_port_bytes).await
}

// ─── Shared SOCKS5 handshake ─────────────────────────────────────────────────

async fn do_socks5_handshake<S>(
    stream: &mut S,
    target_ip_bytes: &[u8; 4],
    target_port_bytes: &[u8; 2],
) -> bool
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    // 1. Greeting
    if stream.write_all(&[0x05, 0x01, 0x00]).await.is_err() {
        return false;
    }

    let mut greeting_resp = [0u8; 2];
    if stream.read_exact(&mut greeting_resp).await.is_err() {
        return false;
    }
    if greeting_resp != [0x05, 0x00] {
        return false;
    }

    // 2. CONNECT request (IPv4)
    let mut req = [0u8; 10];
    req[0] = 0x05;
    req[1] = 0x01;
    req[2] = 0x00;
    req[3] = 0x01; // ATYP = IPv4
    req[4..8].copy_from_slice(target_ip_bytes);
    req[8..10].copy_from_slice(target_port_bytes);
    if stream.write_all(&req).await.is_err() {
        return false;
    }

    // 3. CONNECT response
    let mut connect_resp = [0u8; 10];
    if stream.read_exact(&mut connect_resp).await.is_err() {
        return false;
    }
    connect_resp[1] == 0x00
}

// ─── Main ─────────────────────────────────────────────────────────────────────

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Explicit multi-thread runtime: default #workers = logical CPUs.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    rt.block_on(async_main(args))
}

async fn async_main(args: Args) -> Result<(), Box<dyn std::error::Error>> {
    let proxy_addr: SocketAddr =
        format!("{}:{}", args.proxy_host, args.proxy_port).parse()?;
    let target_ip = Ipv4Addr::from_str(&args.target_host)?;
    let target_ip_bytes = target_ip.octets();
    let target_port_bytes = args.target_port.to_be_bytes();
    let proxy_uds: Option<Arc<String>> = args.proxy_uds.map(Arc::new);

    let success_count = Arc::new(AtomicU64::new(0));
    let fail_count = Arc::new(AtomicU64::new(0));
    let running = Arc::new(AtomicBool::new(true));

    if proxy_uds.is_some() {
        println!("Proxy:  unix://{}", proxy_uds.as_ref().unwrap());
    } else {
        println!("Proxy:  {}", proxy_addr);
    }
    println!("Target: {}:{}", args.target_host, args.target_port);
    println!("Concurrency: {}, Duration: {}s", args.concurrency, args.duration);
    println!("Starting SOCKS5 CPS benchmark...");

    let start_time = Instant::now();
    let mut tasks = Vec::with_capacity(args.concurrency);

    for _ in 0..args.concurrency {
        let success_count = Arc::clone(&success_count);
        let fail_count = Arc::clone(&fail_count);
        let running = Arc::clone(&running);
        let proxy_uds = proxy_uds.clone();

        let task = tokio::spawn(async move {
            while running.load(Ordering::Relaxed) {
                let ok = if let Some(ref path) = proxy_uds {
                    test_socks5_uds(path, target_ip_bytes, target_port_bytes).await
                } else {
                    test_socks5_tcp(proxy_addr, target_ip_bytes, target_port_bytes).await
                };
                if ok {
                    success_count.fetch_add(1, Ordering::Relaxed);
                } else {
                    fail_count.fetch_add(1, Ordering::Relaxed);
                }
            }
        });
        tasks.push(task);
    }

    tokio::time::sleep(Duration::from_secs(args.duration)).await;
    running.store(false, Ordering::Relaxed);

    for task in tasks {
        let _ = task.await;
    }

    let elapsed = start_time.elapsed().as_secs_f64();
    let total_success = success_count.load(Ordering::Relaxed);
    let total_fail = fail_count.load(Ordering::Relaxed);
    let cps = total_success as f64 / elapsed;

    println!("\n=== Consolidated Results ===");
    println!("Total Successful Connections: {}", total_success);
    println!("Total Failed Connections:     {}", total_fail);
    println!("Max Elapsed Time:             {:.2}s", elapsed);
    println!("Combined Connections Per Second (CPS): {:.2}", cps);

    Ok(())
}
