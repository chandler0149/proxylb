use std::io;
use std::net::SocketAddr;
use tokio::net::UdpSocket;
use crate::outbound::TargetAddr;

/// Creates a tuned UDP socket with 4MB send/recv buffers to prevent packet drops
pub fn create_tuned_udp_socket() -> io::Result<UdpSocket> {
    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    socket.set_nonblocking(true)?;
    
    let _ = socket.set_recv_buffer_size(4 * 1024 * 1024);
    let _ = socket.set_send_buffer_size(4 * 1024 * 1024);
    
    let addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
    socket.bind(&addr.into())?;
    
    let std_sock: std::net::UdpSocket = socket.into();
    UdpSocket::from_std(std_sock)
}

/// An active UDP session bound to a specific backend.
pub enum UdpBackendSession {
    Direct {
        socket: UdpSocket,
    },
    Shadowsocks {
        socket: shadowsocks::relay::udprelay::ProxySocket<shadowsocks::net::UdpSocket>,
        server_addr: SocketAddr,
    },
    Socks5 {
        socket: UdpSocket,
        backend_relay_addr: SocketAddr,
        // The TCP stream must be kept alive for the duration of the SOCKS5 UDP association
        _tcp: tokio::sync::Mutex<crate::outbound::BackendStream>,
    },
}

impl UdpBackendSession {
    pub async fn send_to(&self, buf: &[u8], target: &TargetAddr) -> io::Result<usize> {
        match self {
            UdpBackendSession::Direct { socket } => {
                match target {
                    TargetAddr::Ip(addr) => socket.send_to(buf, addr).await,
                    TargetAddr::Domain(host, port) => {
                        // Resolve domain locally for direct UDP
                        if let Ok(mut addrs) = tokio::net::lookup_host((host.as_str(), *port)).await {
                            if let Some(addr) = addrs.next() {
                                socket.send_to(buf, &addr).await
                            } else {
                                Err(io::Error::new(io::ErrorKind::NotFound, "dns resolution failed"))
                            }
                        } else {
                            Err(io::Error::new(io::ErrorKind::NotFound, "dns resolution failed"))
                        }
                    }
                }
            }
            UdpBackendSession::Shadowsocks { socket, server_addr } => {
                let ss_addr = crate::outbound::shadowsocks::to_ss_address(target);
                socket.send_to(*server_addr, &ss_addr, buf).await.map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))
            }
            UdpBackendSession::Socks5 { socket, backend_relay_addr, .. } => {
                // Prepend SOCKS5 UDP header
                let mut packet = Vec::with_capacity(buf.len() + 262);
                packet.extend_from_slice(&[0x00, 0x00, 0x00]); // RSV, FRAG
                let mut addr_buf = [0u8; 259];
                let addr_len = crate::outbound::socks5::write_target_addr_to_buf(target, &mut addr_buf)?;
                packet.extend_from_slice(&addr_buf[..addr_len]);
                packet.extend_from_slice(buf);
                socket.send_to(&packet, backend_relay_addr).await
            }
        }
    }

    pub async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, TargetAddr)> {
        match self {
            UdpBackendSession::Direct { socket } => {
                let (len, addr) = socket.recv_from(buf).await?;
                Ok((len, TargetAddr::Ip(addr)))
            }
            UdpBackendSession::Shadowsocks { socket, .. } => {
                let (len, _server, addr, _extra) = socket.recv_from(buf).await.map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                let target = match addr {
                    shadowsocks::relay::Address::SocketAddress(sa) => TargetAddr::Ip(sa),
                    shadowsocks::relay::Address::DomainNameAddress(host, port) => TargetAddr::Domain(host, port),
                };
                Ok((len, target))
            }
            UdpBackendSession::Socks5 { socket, .. } => {
                // A buffer large enough to receive SOCKS5 header + payload
                let mut temp_buf = vec![0u8; buf.len() + 256];
                let (len, _src) = socket.recv_from(&mut temp_buf).await?;
                if len < 4 {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "packet too small"));
                }
                // temp_buf[0..2] is RSV
                // temp_buf[2] is FRAG
                if temp_buf[2] != 0 {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "SOCKS5 UDP fragmentation not supported"));
                }
                let (target, header_len) = crate::inbound::socks5::parse_target_addr_from_buf(&temp_buf[3..len])?;
                let payload_len = len - 3 - header_len;
                buf[..payload_len].copy_from_slice(&temp_buf[3 + header_len..len]);
                Ok((payload_len, target))
            }
        }
    }
}
