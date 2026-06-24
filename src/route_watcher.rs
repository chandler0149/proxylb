#[cfg(target_os = "linux")]
pub fn start_route_watcher(
    ancillary_handle: &tokio::runtime::Handle,
    tx: tokio::sync::watch::Sender<u64>,
) {
    ancillary_handle.spawn_blocking(move || {
        unsafe {
            let fd = libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_ROUTE);
            if fd < 0 {
                tracing::warn!("Failed to create netlink socket for route monitoring");
                return;
            }

            let mut addr: libc::sockaddr_nl = std::mem::zeroed();
            addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
            // RTMGRP_IPV4_ROUTE (0x40) | RTMGRP_IPV6_ROUTE (0x80)
            addr.nl_groups = 0x40 | 0x80;

            let addr_ptr = &addr as *const libc::sockaddr_nl as *const libc::sockaddr;
            let addr_len = std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t;

            if libc::bind(fd, addr_ptr, addr_len) < 0 {
                tracing::warn!("Failed to bind netlink socket for route monitoring");
                libc::close(fd);
                return;
            }

            let mut epoch = 0u64;
            let mut buf = [0u8; 4096];
            loop {
                let n = libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0);
                if n <= 0 {
                    libc::close(fd);
                    break;
                }
                
                let mut changed = false;
                let mut offset = 0;
                while offset + std::mem::size_of::<libc::nlmsghdr>() <= n as usize {
                    let nlh = &*(buf.as_ptr().add(offset) as *const libc::nlmsghdr);
                    if nlh.nlmsg_len < std::mem::size_of::<libc::nlmsghdr>() as u32 {
                        break;
                    }
                    let mtype = nlh.nlmsg_type;
                    if mtype == libc::RTM_NEWROUTE || mtype == libc::RTM_DELROUTE {
                        changed = true;
                        break;
                    }
                    offset += (nlh.nlmsg_len as usize + 3) & !3; // ALIGN
                }

                if changed {
                    epoch += 1;
                    if tx.send(epoch).is_err() {
                        libc::close(fd);
                        break;
                    }
                }
            }
        }
    });
}

#[cfg(target_os = "macos")]
pub fn start_route_watcher(
    ancillary_handle: &tokio::runtime::Handle,
    tx: tokio::sync::watch::Sender<u64>,
) {
    ancillary_handle.spawn_blocking(move || unsafe {
        let fd = libc::socket(libc::PF_ROUTE, libc::SOCK_RAW, libc::AF_UNSPEC);
        if fd < 0 {
            tracing::warn!("Failed to create routing socket for route monitoring");
            return;
        }

        let mut epoch = 0u64;
        let mut buf = [0u8; 4096];
        loop {
            let n = libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0);
            if n <= 0 {
                libc::close(fd);
                break;
            }
            
            let mut changed = false;
            if n as usize >= std::mem::size_of::<libc::rt_msghdr>() {
                let rtm = &*(buf.as_ptr() as *const libc::rt_msghdr);
                let mtype = rtm.rtm_type as i32;
                if mtype == libc::RTM_ADD || mtype == libc::RTM_DELETE {
                    changed = true;
                }
            }

            if changed {
                epoch += 1;
                if tx.send(epoch).is_err() {
                    libc::close(fd);
                    break;
                }
            }
        }
    });
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn start_route_watcher(
    _ancillary_handle: &tokio::runtime::Handle,
    _tx: tokio::sync::watch::Sender<u64>,
) {
}
