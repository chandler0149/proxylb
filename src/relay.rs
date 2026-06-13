//! Bidirectional relay between two async streams.
//!
//! Wraps `tokio::io::copy_bidirectional` with byte-count tracking and logging.
//! If both streams are raw files/sockets on Linux, it utilizes zero-copy `splice`.

use std::sync::OnceLock;
use tokio::io::{AsyncRead, AsyncWrite};

#[cfg(unix)]
use std::os::unix::io::RawFd;

#[cfg(unix)]
#[derive(Debug, Clone, Copy)]
pub enum RawStreamRef<'a> {
    Tcp(&'a tokio::net::TcpStream),
    Unix(&'a tokio::net::UnixStream),
}

#[cfg(unix)]
impl<'a> RawStreamRef<'a> {
    pub fn as_raw_fd(&self) -> RawFd {
        use std::os::unix::io::AsRawFd;
        match self {
            RawStreamRef::Tcp(s) => s.as_raw_fd(),
            RawStreamRef::Unix(s) => s.as_raw_fd(),
        }
    }

    pub async fn async_io<R>(
        &self,
        interest: tokio::io::Interest,
        f: impl FnMut() -> std::io::Result<R>,
    ) -> std::io::Result<R> {
        match self {
            RawStreamRef::Tcp(s) => s.async_io(interest, f).await,
            RawStreamRef::Unix(s) => s.async_io(interest, f).await,
        }
    }
}

#[cfg(unix)]
pub trait AsRawStreamRef {
    fn as_raw_stream_ref(&self) -> Option<RawStreamRef<'_>>;

    #[cfg(target_os = "linux")]
    fn take_preallocated_pipes(&mut self) -> Option<PreallocatedPipes> {
        None
    }
}

#[cfg(not(unix))]
pub trait AsRawStreamRef {
    fn as_raw_stream_ref(&self) -> Option<()> {
        None
    }
}

// Implement AsRawStreamRef for TcpStream
#[cfg(unix)]
impl AsRawStreamRef for tokio::net::TcpStream {
    fn as_raw_stream_ref(&self) -> Option<RawStreamRef<'_>> {
        Some(RawStreamRef::Tcp(self))
    }
}

// Implement AsRawStreamRef for UnixStream
#[cfg(unix)]
impl AsRawStreamRef for tokio::net::UnixStream {
    fn as_raw_stream_ref(&self) -> Option<RawStreamRef<'_>> {
        Some(RawStreamRef::Unix(self))
    }
}

pub static ZERO_COPY_ENABLED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(true);

/// Global sender used to defer stream drops off the tokio worker threads.
/// The item type is type-erased so any stream (`BackendStream`, inbound `TcpStream`, etc.)
/// can be sent to the same closer thread.
/// Populated by [`init_deferred_dropper`] before the worker runtime starts.
static STREAM_DROP_TX: OnceLock<flume::Sender<Box<dyn Send + 'static>>> = OnceLock::new();

/// Spawn a dedicated std thread that receives and drops stream values,
/// keeping `close(2)` / TCP teardown completely off the worker runtime.
///
/// `closer_core` — if `Some`, the thread is pinned to that logical CPU core.
pub fn init_deferred_dropper(closer_core: Option<usize>) {
    let (tx, rx) = flume::unbounded::<Box<dyn Send + 'static>>();
    // Ignore the error if already initialised (idempotent on hot-reload).
    let _ = STREAM_DROP_TX.set(tx);

    std::thread::Builder::new()
        .name("proxylb-fd-closer".into())
        .spawn(move || {
            if let Some(core_num) = closer_core {
                if let Some(core_ids) = core_affinity::get_core_ids() {
                    if let Some(core_id) = core_ids.into_iter().find(|c| c.id == core_num) {
                        if core_affinity::set_for_current(core_id) {
                            tracing::info!("proxylb-fd-closer pinned to CPU core {}", core_num);
                        }
                    }
                }
            }
            // Drain until all senders are gone (process exit or channel drop).
            while rx.recv().is_ok() { /* actual close(2) happens here */ }
        })
        .expect("failed to spawn fd-closer thread");
}

/// Send `stream` to the fd-closer thread so that `close(2)` / TCP teardown
/// happens off the tokio worker runtime. Falls back to an immediate drop if
/// the closer has not been initialised or the send fails.
#[inline]
pub fn defer_drop(stream: impl Send + 'static) {
    if let Some(tx) = STREAM_DROP_TX.get() {
        let _ = tx.try_send(Box::new(stream));
        // On failure the Box is dropped here — correct, just not deferred.
    }
    // If not initialised: drop immediately (correct, just not deferred).
}

/// Relay data bidirectionally between two streams until one side closes.
///
/// Returns (bytes_client_to_backend, bytes_backend_to_client).
pub async fn relay<A, B>(client: &mut A, backend: &mut B) -> std::io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin + AsRawStreamRef,
    B: AsyncRead + AsyncWrite + Unpin + AsRawStreamRef,
{
    if ZERO_COPY_ENABLED.load(std::sync::atomic::Ordering::Relaxed) {
        #[cfg(target_os = "linux")]
        {
            let pipes = client
                .take_preallocated_pipes()
                .or_else(|| backend.take_preallocated_pipes());
            if let (Some(stream_a), Some(stream_b)) =
                (client.as_raw_stream_ref(), backend.as_raw_stream_ref())
            {
                if let Ok(res) = splice_bidirectional_with_pipes(stream_a, stream_b, pipes).await {
                    return Ok(res);
                }
            }
        }
    }

    tokio::io::copy_bidirectional(client, backend).await
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
pub struct OwnedFd(pub RawFd);

#[cfg(target_os = "linux")]
impl Drop for OwnedFd {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.0);
        }
    }
}

#[cfg(target_os = "linux")]
impl std::os::unix::io::AsRawFd for OwnedFd {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
pub struct PreallocatedPipes {
    pub pipe1_rd: OwnedFd,
    pub pipe1_wr: OwnedFd,
    pub pipe2_rd: OwnedFd,
    pub pipe2_wr: OwnedFd,
}

#[cfg(target_os = "linux")]
pub fn create_preallocated_pipes() -> Option<PreallocatedPipes> {
    let (p1_rd, p1_wr) = create_pipe().ok()?;
    // Wrap immediately so the FDs are closed if the second pipe() call fails.
    let (pipe1_rd, pipe1_wr) = (OwnedFd(p1_rd), OwnedFd(p1_wr));
    let (p2_rd, p2_wr) = create_pipe().ok()?;
    Some(PreallocatedPipes {
        pipe1_rd,
        pipe1_wr,
        pipe2_rd: OwnedFd(p2_rd),
        pipe2_wr: OwnedFd(p2_wr),
    })
}

#[cfg(target_os = "linux")]
struct ShutdownGuard(RawFd);

#[cfg(target_os = "linux")]
impl Drop for ShutdownGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = libc::shutdown(self.0, libc::SHUT_WR);
        }
    }
}

#[cfg(target_os = "linux")]
fn create_pipe() -> std::io::Result<(RawFd, RawFd)> {
    let mut fds = [0; 2];
    let res = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_NONBLOCK | libc::O_CLOEXEC) };
    if res == -1 {
        return Err(std::io::Error::last_os_error());
    }
    Ok((fds[0], fds[1]))
}

#[cfg(target_os = "linux")]
async fn splice_one_way(
    r_stream: RawStreamRef<'_>,
    w_stream: RawStreamRef<'_>,
    pipe_rd: OwnedFd,
    pipe_wr: OwnedFd,
) -> std::io::Result<u64> {
    use std::os::unix::io::AsRawFd;

    let mut total_bytes = 0;
    let r_fd = r_stream.as_raw_fd();
    let w_fd = w_stream.as_raw_fd();

    let _shutdown_guard = ShutdownGuard(w_fd);

    loop {
        // Wait for readability on read stream, then splice from read stream into the pipe
        let res = r_stream
            .async_io(tokio::io::Interest::READABLE, || {
                let res = unsafe {
                    libc::splice(
                        r_fd,
                        std::ptr::null_mut(),
                        pipe_wr.as_raw_fd(),
                        std::ptr::null_mut(),
                        1048576, // 1M chunk size
                        libc::SPLICE_F_NONBLOCK | libc::SPLICE_F_MOVE,
                    )
                };
                if res < 0 {
                    let err = std::io::Error::last_os_error();
                    if err.kind() == std::io::ErrorKind::WouldBlock {
                        return Err(err);
                    }
                    return Err(err);
                }
                Ok(res)
            })
            .await?;

        let spliced = res as usize;
        if spliced == 0 {
            break; // EOF
        }

        // Splice out of the pipe into the write stream
        let mut written = 0;
        while written < spliced {
            let res = w_stream
                .async_io(tokio::io::Interest::WRITABLE, || {
                    let res = unsafe {
                        libc::splice(
                            pipe_rd.as_raw_fd(),
                            std::ptr::null_mut(),
                            w_fd,
                            std::ptr::null_mut(),
                            spliced - written,
                            libc::SPLICE_F_NONBLOCK | libc::SPLICE_F_MOVE,
                        )
                    };
                    if res < 0 {
                        let err = std::io::Error::last_os_error();
                        if err.kind() == std::io::ErrorKind::WouldBlock {
                            return Err(err);
                        }
                        return Err(err);
                    }
                    Ok(res)
                })
                .await?;
            written += res as usize;
        }
        total_bytes += written as u64;
    }
    Ok(total_bytes)
}

#[cfg(target_os = "linux")]
pub async fn splice_bidirectional_with_pipes(
    stream_a: RawStreamRef<'_>,
    stream_b: RawStreamRef<'_>,
    pipes: Option<PreallocatedPipes>,
) -> std::io::Result<(u64, u64)> {
    let (pipe1_rd, pipe1_wr, pipe2_rd, pipe2_wr) = match pipes {
        Some(p) => (p.pipe1_rd, p.pipe1_wr, p.pipe2_rd, p.pipe2_wr),
        None => {
            let (p1_rd, p1_wr) = create_pipe()?;
            let (p2_rd, p2_wr) = create_pipe()?;
            (
                OwnedFd(p1_rd),
                OwnedFd(p1_wr),
                OwnedFd(p2_rd),
                OwnedFd(p2_wr),
            )
        }
    };

    let task_a_to_b = splice_one_way(stream_a, stream_b, pipe1_rd, pipe1_wr);
    let task_b_to_a = splice_one_way(stream_b, stream_a, pipe2_rd, pipe2_wr);

    let (res_ab, res_ba) = tokio::join!(task_a_to_b, task_b_to_a);
    Ok((res_ab?, res_ba?))
}
