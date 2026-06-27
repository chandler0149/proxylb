//! Lean SOCKS5h outbound client.
//!
//! Implements just enough of RFC 1928 to issue a CONNECT request with a
//! domain name (ATYP=0x03, i.e. "socks5h") through a SOCKS5 backend.

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::{BackendStream, TargetAddr};
use crate::backend::BackendInfo;

/// SOCKS5 protocol constants.
const SOCKS5_VERSION: u8 = 0x05;
const AUTH_NONE: u8 = 0x00;
const AUTH_USER_PASS: u8 = 0x02;
const CMD_CONNECT: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV4: u8 = 0x01;
const ATYP_IPV6: u8 = 0x04;

/// Connect to a SOCKS5h backend and issue a CONNECT to `target`.
pub async fn socks5h_connect(
    backend: &BackendInfo,
    target: &TargetAddr,
    timeout: Duration,
) -> io::Result<BackendStream> {
    let stream = crate::outbound::connect_endpoint(backend, timeout).await?;
    let stream = socks5h_authenticate(stream, backend).await?;
    socks5h_connect_target(stream, target).await
}

/// Phase 1: SOCKS5 auth negotiation on an already-connected stream.
pub async fn socks5h_authenticate<S>(mut stream: S, backend: &BackendInfo) -> io::Result<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // === Step 1: Auth negotiation ===
    if backend.requires_auth() {
        // Offer both no-auth and user/pass
        stream
            .write_all(&[SOCKS5_VERSION, 2, AUTH_NONE, AUTH_USER_PASS])
            .await?;
    } else {
        stream.write_all(&[SOCKS5_VERSION, 1, AUTH_NONE]).await?;
    }

    // Read method selection response: [version, method]
    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp).await?;
    if resp[0] != SOCKS5_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("backend returned SOCKS version {}, expected 5", resp[0]),
        ));
    }

    match resp[1] {
        AUTH_NONE => { /* No auth needed */ }
        AUTH_USER_PASS => {
            // RFC 1929: username/password sub-negotiation
            let user = backend
                .username
                .as_deref()
                .ok_or_else(|| io::Error::other("backend wants auth but no username configured"))?;
            let pass = backend
                .password
                .as_deref()
                .ok_or_else(|| io::Error::other("backend wants auth but no password configured"))?;

            let mut auth_req = Vec::with_capacity(3 + user.len() + pass.len());
            auth_req.push(0x01); // sub-negotiation version
            auth_req.push(user.len() as u8);
            auth_req.extend_from_slice(user.as_bytes());
            auth_req.push(pass.len() as u8);
            auth_req.extend_from_slice(pass.as_bytes());
            stream.write_all(&auth_req).await?;

            let mut auth_resp = [0u8; 2];
            stream.read_exact(&mut auth_resp).await?;
            if auth_resp[1] != 0x00 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "backend SOCKS5 auth failed",
                ));
            }
        }
        0xFF => {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "backend rejected all auth methods",
            ));
        }
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("backend selected unsupported auth method: {:#x}", other),
            ));
        }
    }

    Ok(stream)
}

/// Phase 2: Issue a SOCKS5 CONNECT request to `target` on an already-authenticated stream.
pub async fn socks5h_connect_target<S>(mut stream: S, target: &TargetAddr) -> io::Result<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // === Step 2: CONNECT request ===
    let mut req = [0u8; 262];
    let req_len = build_connect_request_buf(target, &mut req)?;
    stream.write_all(&req[..req_len]).await?;

    // === Step 3: Read CONNECT response ===
    let mut resp_header = [0u8; 4];
    stream.read_exact(&mut resp_header).await?;

    if resp_header[0] != SOCKS5_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid SOCKS5 CONNECT response version",
        ));
    }
    if resp_header[1] != 0x00 {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!(
                "SOCKS5 CONNECT failed with reply code: {:#x}",
                resp_header[1]
            ),
        ));
    }

    // Skip the bind address
    match resp_header[3] {
        ATYP_IPV4 => {
            let mut skip = [0u8; 4 + 2]; // IPv4 + port
            stream.read_exact(&mut skip).await?;
        }
        ATYP_IPV6 => {
            let mut skip = [0u8; 16 + 2]; // IPv6 + port
            stream.read_exact(&mut skip).await?;
        }
        ATYP_DOMAIN => {
            let mut len_buf = [0u8; 1];
            stream.read_exact(&mut len_buf).await?;
            let skip_len = len_buf[0] as usize + 2;
            let mut skip = [0u8; 257]; // Max domain length is 255 + 2 bytes for port
            stream.read_exact(&mut skip[..skip_len]).await?;
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unknown ATYP in CONNECT response",
            ));
        }
    }

    Ok(stream)
}

/// Build a SOCKS5 CONNECT request packet into a pre-allocated stack buffer.
fn build_connect_request_buf(target: &TargetAddr, buf: &mut [u8]) -> io::Result<usize> {
    buf[0] = SOCKS5_VERSION;
    buf[1] = CMD_CONNECT;
    buf[2] = 0x00; // RSV
    
    let addr_len = write_target_addr_to_buf(target, &mut buf[3..])?;
    Ok(3 + addr_len)
}

pub fn write_target_addr_to_buf(target: &TargetAddr, buf: &mut [u8]) -> io::Result<usize> {
    match target {
        TargetAddr::Domain(host, port) => {
            let host_bytes = host.as_bytes();
            if host_bytes.len() > 255 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "domain name too long for SOCKS5",
                ));
            }
            if buf.len() < 1 + 1 + host_bytes.len() + 2 {
                return Err(io::Error::new(io::ErrorKind::WriteZero, "buffer too small"));
            }
            buf[0] = ATYP_DOMAIN;
            buf[1] = host_bytes.len() as u8;
            buf[2..2 + host_bytes.len()].copy_from_slice(host_bytes);
            let port_idx = 2 + host_bytes.len();
            buf[port_idx] = (port >> 8) as u8;
            buf[port_idx + 1] = *port as u8;
            Ok(port_idx + 2)
        }
        TargetAddr::Ip(addr) => {
            match addr {
                SocketAddr::V4(v4) => {
                    if buf.len() < 1 + 4 + 2 {
                        return Err(io::Error::new(io::ErrorKind::WriteZero, "buffer too small"));
                    }
                    buf[0] = ATYP_IPV4;
                    buf[1..5].copy_from_slice(&v4.ip().octets());
                    buf[5] = (v4.port() >> 8) as u8;
                    buf[6] = v4.port() as u8;
                    Ok(7)
                }
                SocketAddr::V6(v6) => {
                    if buf.len() < 1 + 16 + 2 {
                        return Err(io::Error::new(io::ErrorKind::WriteZero, "buffer too small"));
                    }
                    buf[0] = ATYP_IPV6;
                    buf[1..17].copy_from_slice(&v6.ip().octets());
                    buf[17] = (v6.port() >> 8) as u8;
                    buf[18] = v6.port() as u8;
                    Ok(19)
                }
            }
        }
    }
}

/// Phase 2: Issue a SOCKS5 UDP ASSOCIATE request on an already-authenticated stream.
pub async fn socks5h_udp_associate<S>(mut stream: S) -> io::Result<(S, SocketAddr)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut req = [0u8; 10];
    req[0] = SOCKS5_VERSION;
    req[1] = 0x03; // UDP ASSOCIATE
    req[2] = 0x00; // RSV
    req[3] = ATYP_IPV4;
    req[4..8].copy_from_slice(&[0, 0, 0, 0]);
    req[8..10].copy_from_slice(&[0, 0]);
    stream.write_all(&req).await?;

    let mut resp_header = [0u8; 4];
    stream.read_exact(&mut resp_header).await?;

    if resp_header[0] != SOCKS5_VERSION {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid SOCKS5 UDP ASSOCIATE response version"));
    }
    if resp_header[1] != 0x00 {
        return Err(io::Error::new(io::ErrorKind::ConnectionRefused, format!("SOCKS5 UDP ASSOCIATE failed with reply code: {:#x}", resp_header[1])));
    }

    let addr = match resp_header[3] {
        ATYP_IPV4 => {
            let mut ip = [0u8; 4];
            let mut port = [0u8; 2];
            stream.read_exact(&mut ip).await?;
            stream.read_exact(&mut port).await?;
            SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::from(ip)), u16::from_be_bytes(port))
        }
        ATYP_IPV6 => {
            let mut ip = [0u8; 16];
            let mut port = [0u8; 2];
            stream.read_exact(&mut ip).await?;
            stream.read_exact(&mut port).await?;
            SocketAddr::new(std::net::IpAddr::V6(std::net::Ipv6Addr::from(ip)), u16::from_be_bytes(port))
        }
        ATYP_DOMAIN => {
            let mut len_buf = [0u8; 1];
            stream.read_exact(&mut len_buf).await?;
            let len = len_buf[0] as usize;
            let mut host = vec![0u8; len];
            stream.read_exact(&mut host).await?;
            let mut port = [0u8; 2];
            stream.read_exact(&mut port).await?;
            let host_str = String::from_utf8_lossy(&host).to_string();
            let port_u16 = u16::from_be_bytes(port);
            if let Ok(mut addrs) = tokio::net::lookup_host((host_str.as_str(), port_u16)).await {
                if let Some(addr) = addrs.next() {
                    addr
                } else {
                    return Err(io::Error::new(io::ErrorKind::NotFound, "dns resolution failed for SOCKS5 UDP relay address"));
                }
            } else {
                return Err(io::Error::new(io::ErrorKind::NotFound, "dns resolution failed for SOCKS5 UDP relay address"));
            }
        }
        _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "unknown ATYP in UDP ASSOCIATE response")),
    };

    Ok((stream, addr))
}
