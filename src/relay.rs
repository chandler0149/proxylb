//! Bidirectional relay between two async streams.
//!
//! Wraps `tokio::io::copy_bidirectional` with byte-count tracking and logging.

use tokio::io::{AsyncRead, AsyncWrite};

/// Relay data bidirectionally between two streams until one side closes.
///
/// Returns (bytes_client_to_backend, bytes_backend_to_client).
pub async fn relay<A, B>(
    client: &mut A,
    backend: &mut B,
) -> std::io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    tokio::io::copy_bidirectional(client, backend).await
}
