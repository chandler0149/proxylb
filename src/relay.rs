//! Bidirectional relay between two async streams.
//!
//! Wraps `tokio::io::copy_bidirectional` with byte-count tracking and logging.
//! If both streams are raw files/sockets on Linux, it utilizes zero-copy `splice`.

use crossbeam_queue::ArrayQueue;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::io::{AsyncRead, AsyncWrite};

static BUFFER_POOL: OnceLock<ArrayQueue<Box<[u8]>>> = OnceLock::new();
const BUFFER_SIZE: usize = 65536;

fn get_buffer_pool() -> &'static ArrayQueue<Box<[u8]>> {
    BUFFER_POOL.get_or_init(|| ArrayQueue::new(1024))
}

#[cfg(target_os = "linux")]
use std::os::unix::io::RawFd;

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy)]
pub enum RawStreamRef<'a> {
    Tcp(&'a tokio::net::TcpStream),
    Unix(&'a tokio::net::UnixStream),
}

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
pub trait AsRawStreamRef {
    fn as_raw_stream_ref(&self) -> Option<RawStreamRef<'_>>;

    #[cfg(target_os = "linux")]
    fn take_preallocated_pipes(&mut self) -> Option<PreallocatedPipes> {
        None
    }
}

#[cfg(not(target_os = "linux"))]
pub trait AsRawStreamRef {
    #[allow(dead_code)]
    fn as_raw_stream_ref(&self) -> Option<()> {
        None
    }
}

#[cfg(not(target_os = "linux"))]
impl<T> AsRawStreamRef for T {}

// Implement AsRawStreamRef for TcpStream
#[cfg(target_os = "linux")]
impl AsRawStreamRef for tokio::net::TcpStream {
    fn as_raw_stream_ref(&self) -> Option<RawStreamRef<'_>> {
        Some(RawStreamRef::Tcp(self))
    }
}

// Implement AsRawStreamRef for UnixStream
#[cfg(target_os = "linux")]
impl AsRawStreamRef for tokio::net::UnixStream {
    fn as_raw_stream_ref(&self) -> Option<RawStreamRef<'_>> {
        Some(RawStreamRef::Unix(self))
    }
}

#[cfg(target_os = "linux")]
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
pub async fn relay<'a, A, B>(
    client: &mut A,
    backend: &mut B,
    up_counters: Vec<&'a AtomicU64>,
    down_counters: Vec<&'a AtomicU64>,
) -> std::io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin + AsRawStreamRef,
    B: AsyncRead + AsyncWrite + Unpin + AsRawStreamRef,
{
    #[cfg(target_os = "linux")]
    if ZERO_COPY_ENABLED.load(std::sync::atomic::Ordering::Relaxed) {
        let pipes = client
            .take_preallocated_pipes()
            .or_else(|| backend.take_preallocated_pipes());
        if let (Some(stream_a), Some(stream_b)) =
            (client.as_raw_stream_ref(), backend.as_raw_stream_ref())
        {
            if let Ok(res) = splice_bidirectional_with_pipes(
                stream_a,
                stream_b,
                pipes,
                up_counters.clone(),
                down_counters.clone(),
            )
            .await
            {
                return Ok(res);
            }
        }
    }

    large_copy_bidirectional_fallback(client, backend, up_counters, down_counters).await
}

struct TransferState<'a> {
    read_done: bool,
    pos: usize,
    cap: usize,
    amt: u64,
    buf: Option<Box<[u8]>>,
    counters: Vec<&'a AtomicU64>,
}

impl<'a> Drop for TransferState<'a> {
    fn drop(&mut self) {
        if let Some(buf) = self.buf.take() {
            let _ = get_buffer_pool().push(buf);
        }
    }
}

impl<'a> TransferState<'a> {
    fn new(counters: Vec<&'a AtomicU64>) -> Self {
        let buf = get_buffer_pool()
            .pop()
            .unwrap_or_else(|| vec![0; BUFFER_SIZE].into_boxed_slice());

        Self {
            read_done: false,
            pos: 0,
            cap: 0,
            amt: 0,
            buf: Some(buf),
            counters,
        }
    }
}

fn transfer_one_direction<'a, R, W>(
    cx: &mut std::task::Context<'_>,
    state: &mut TransferState<'a>,
    r: &mut R,
    w: &mut W,
) -> std::task::Poll<std::io::Result<()>>
where
    R: AsyncRead + Unpin + ?Sized,
    W: AsyncWrite + Unpin + ?Sized,
{
    loop {
        // Read into buffer if empty
        if state.pos == state.cap && !state.read_done {
            let mut buf = tokio::io::ReadBuf::new(state.buf.as_deref_mut().unwrap());
            match std::pin::Pin::new(&mut *r).poll_read(cx, &mut buf) {
                std::task::Poll::Ready(Ok(())) => {
                    if buf.filled().is_empty() {
                        state.read_done = true;
                    } else {
                        state.pos = 0;
                        state.cap = buf.filled().len();
                    }
                }
                std::task::Poll::Ready(Err(e)) => return std::task::Poll::Ready(Err(e)),
                std::task::Poll::Pending => {
                    let _ = std::pin::Pin::new(&mut *w).poll_flush(cx);
                    return std::task::Poll::Pending;
                }
            }
        }

        // Write from buffer if it has data
        if state.pos < state.cap {
            let buf_slice = state.buf.as_deref().unwrap();
            match std::pin::Pin::new(&mut *w).poll_write(cx, &buf_slice[state.pos..state.cap]) {
                std::task::Poll::Ready(Ok(0)) => {
                    return std::task::Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "write zero byte into writer",
                    )));
                }
                std::task::Poll::Ready(Ok(n)) => {
                    state.pos += n;
                    state.amt += n as u64;
                    for c in &state.counters {
                        c.fetch_add(n as u64, Ordering::Relaxed);
                    }
                }
                std::task::Poll::Ready(Err(e)) => return std::task::Poll::Ready(Err(e)),
                std::task::Poll::Pending => return std::task::Poll::Pending,
            }
        }

        // Flush and finish if read is done and buffer is empty
        if state.pos == state.cap && state.read_done {
            match std::pin::Pin::new(&mut *w).poll_flush(cx) {
                std::task::Poll::Ready(Ok(())) => return std::task::Poll::Ready(Ok(())),
                std::task::Poll::Ready(Err(e)) => return std::task::Poll::Ready(Err(e)),
                std::task::Poll::Pending => return std::task::Poll::Pending,
            }
        }
    }
}

struct LargeBidirectionalCopy<'a, A: ?Sized, B: ?Sized> {
    a: &'a mut A,
    b: &'a mut B,
    a_to_b: TransferState<'a>,
    b_to_a: TransferState<'a>,
}

impl<'a, A, B> std::future::Future for LargeBidirectionalCopy<'a, A, B>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    type Output = std::io::Result<(u64, u64)>;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let this = self.get_mut();
        let mut a_to_b_poll =
            transfer_one_direction(cx, &mut this.a_to_b, &mut *this.a, &mut *this.b);
        let mut b_to_a_poll =
            transfer_one_direction(cx, &mut this.b_to_a, &mut *this.b, &mut *this.a);

        // Half-close handling: if one direction is fully done, shutdown the write half on the receiving end.
        if let std::task::Poll::Ready(Ok(())) = a_to_b_poll {
            match std::pin::Pin::new(&mut *this.b).poll_shutdown(cx) {
                std::task::Poll::Ready(Ok(())) => {}
                std::task::Poll::Ready(Err(e)) => return std::task::Poll::Ready(Err(e)),
                std::task::Poll::Pending => {
                    a_to_b_poll = std::task::Poll::Pending;
                }
            }
        }

        if let std::task::Poll::Ready(Ok(())) = b_to_a_poll {
            match std::pin::Pin::new(&mut *this.a).poll_shutdown(cx) {
                std::task::Poll::Ready(Ok(())) => {}
                std::task::Poll::Ready(Err(e)) => return std::task::Poll::Ready(Err(e)),
                std::task::Poll::Pending => {
                    b_to_a_poll = std::task::Poll::Pending;
                }
            }
        }

        match (a_to_b_poll, b_to_a_poll) {
            (std::task::Poll::Ready(Ok(())), std::task::Poll::Ready(Ok(()))) => {
                std::task::Poll::Ready(Ok((this.a_to_b.amt, this.b_to_a.amt)))
            }
            (std::task::Poll::Ready(Err(e)), _) | (_, std::task::Poll::Ready(Err(e))) => {
                std::task::Poll::Ready(Err(e))
            }
            _ => std::task::Poll::Pending,
        }
    }
}

pub async fn large_copy_bidirectional_fallback<'a, A, B>(
    client: &mut A,
    backend: &mut B,
    up_counters: Vec<&'a AtomicU64>,
    down_counters: Vec<&'a AtomicU64>,
) -> std::io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    LargeBidirectionalCopy {
        a: client,
        b: backend,
        a_to_b: TransferState::new(up_counters),
        b_to_a: TransferState::new(down_counters),
    }
    .await
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

    // Attempt to increase the pipe capacity to 1MB (1048576 bytes) for higher throughput.
    // F_SETPIPE_SZ is 1031 in Linux. Ignore errors if we hit hard limits.
    #[cfg(target_os = "linux")]
    unsafe {
        libc::fcntl(fds[1], libc::F_SETPIPE_SZ, 1048576);
    }

    Ok((fds[0], fds[1]))
}

#[cfg(target_os = "linux")]
struct DeferredFd(Option<OwnedFd>);

#[cfg(target_os = "linux")]
impl Drop for DeferredFd {
    fn drop(&mut self) {
        if let Some(fd) = self.0.take() {
            defer_drop(fd);
        }
    }
}

#[cfg(target_os = "linux")]
impl std::ops::Deref for DeferredFd {
    type Target = OwnedFd;

    fn deref(&self) -> &Self::Target {
        self.0.as_ref().unwrap()
    }
}

#[cfg(target_os = "linux")]
async fn splice_one_way<'a>(
    r_stream: RawStreamRef<'_>,
    w_stream: RawStreamRef<'_>,
    pipe_rd: OwnedFd,
    pipe_wr: OwnedFd,
    counters: Vec<&'a AtomicU64>,
) -> std::io::Result<u64> {
    use std::os::unix::io::AsRawFd;

    // Wrap the FDs so they are sent to the fd-closer thread when dropped.
    let pipe_rd = DeferredFd(Some(pipe_rd));
    let pipe_wr = DeferredFd(Some(pipe_wr));

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
        for c in &counters {
            c.fetch_add(written as u64, Ordering::Relaxed);
        }
    }
    Ok(total_bytes)
}

#[cfg(target_os = "linux")]
pub async fn splice_bidirectional_with_pipes<'a>(
    stream_a: RawStreamRef<'_>,
    stream_b: RawStreamRef<'_>,
    pipes: Option<PreallocatedPipes>,
    up_counters: Vec<&'a AtomicU64>,
    down_counters: Vec<&'a AtomicU64>,
) -> std::io::Result<(u64, u64)> {
    let (pipe1_rd, pipe1_wr, pipe2_rd, pipe2_wr) = match pipes {
        Some(p) => (p.pipe1_rd, p.pipe1_wr, p.pipe2_rd, p.pipe2_wr),
        None => {
            let (p1_rd, p1_wr) = create_pipe()?;
            let (pipe1_rd, pipe1_wr) = (OwnedFd(p1_rd), OwnedFd(p1_wr));
            let (p2_rd, p2_wr) = create_pipe()?;
            (pipe1_rd, pipe1_wr, OwnedFd(p2_rd), OwnedFd(p2_wr))
        }
    };

    let task_a_to_b = splice_one_way(stream_a, stream_b, pipe1_rd, pipe1_wr, up_counters);
    let task_b_to_a = splice_one_way(stream_b, stream_a, pipe2_rd, pipe2_wr, down_counters);

    let (res_ab, res_ba) = tokio::join!(task_a_to_b, task_b_to_a);
    Ok((res_ab?, res_ba?))
}
