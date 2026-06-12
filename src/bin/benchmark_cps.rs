use clap::Parser;
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Parser, Debug)]
#[command(name = "benchmark_cps", about = "SOCKS5 CPS Benchmarker in Rust")]
struct Args {
    #[arg(long, default_value = "127.0.0.1")]
    proxy_host: String,

    #[arg(long, default_value = "1080")]
    proxy_port: u16,

    #[arg(long, default_value = "127.0.0.1")]
    target_host: String,

    #[arg(long, default_value = "10800")]
    target_port: u16,

    #[arg(long, default_value = "300")]
    concurrency: usize,

    #[arg(long, default_value = "10")]
    duration: u64,
}

async fn test_socks5_connection(
    proxy_addr: &str,
    target_ip_bytes: &[u8; 4],
    target_port_bytes: &[u8; 2],
) -> bool {
    let mut stream = match TcpStream::connect(proxy_addr).await {
        Ok(s) => s,
        Err(_) => return false,
    };

    // 1. Send SOCKS5 greeting
    if stream.write_all(&[0x05, 0x01, 0x00]).await.is_err() {
        return false;
    }

    // 2. Read SOCKS5 greeting response (2 bytes)
    let mut greeting_resp = [0u8; 2];
    if stream.read_exact(&mut greeting_resp).await.is_err() {
        return false;
    }
    if greeting_resp != [0x05, 0x00] {
        return false;
    }

    // 3. Send SOCKS5 CONNECT request
    let mut req = [0u8; 10];
    req[0] = 0x05;
    req[1] = 0x01;
    req[2] = 0x00;
    req[3] = 0x01;
    req[4..8].copy_from_slice(target_ip_bytes);
    req[8..10].copy_from_slice(target_port_bytes);

    if stream.write_all(&req).await.is_err() {
        return false;
    }

    // 4. Read SOCKS5 CONNECT response (10 bytes)
    let mut connect_resp = [0u8; 10];
    if stream.read_exact(&mut connect_resp).await.is_err() {
        return false;
    }
    if connect_resp[1] != 0x00 {
        return false;
    }

    true
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let proxy_addr = format!("{}:{}", args.proxy_host, args.proxy_port);
    let target_ip = Ipv4Addr::from_str(&args.target_host)?;
    let target_ip_bytes = target_ip.octets();
    let target_port_bytes = args.target_port.to_be_bytes();

    let success_count = Arc::new(AtomicU64::new(0));
    let fail_count = Arc::new(AtomicU64::new(0));
    let running = Arc::new(AtomicBool::new(true));

    println!("Starting SOCKS5 CPS benchmark...");
    println!("Proxy: {}", proxy_addr);
    println!("Target: {}:{}", args.target_host, args.target_port);
    println!(
        "Concurrency: {}, Duration: {}s",
        args.concurrency, args.duration
    );

    let start_time = Instant::now();
    let mut tasks = Vec::with_capacity(args.concurrency);

    for _ in 0..args.concurrency {
        let proxy_addr = proxy_addr.clone();
        let success_count = Arc::clone(&success_count);
        let fail_count = Arc::clone(&fail_count);
        let running = Arc::clone(&running);

        let task = tokio::spawn(async move {
            while running.load(Ordering::Relaxed) {
                if test_socks5_connection(&proxy_addr, &target_ip_bytes, &target_port_bytes).await {
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
    println!("Total Failed Connections: {}", total_fail);
    println!("Max Elapsed Time: {:.2}s", elapsed);
    println!("Combined Connections Per Second (CPS): {:.2}", cps);

    Ok(())
}
