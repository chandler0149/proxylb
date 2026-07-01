use bytes::{Buf, Bytes};
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;

use super::protocol::{CMD_FIN, CMD_PSH, CMD_SYN, Frame};
use super::session::SessionManager;

enum WriteState {
    Init,
    TargetWritten,
}

pub struct AnytlsStream {
    stream_id: u32,
    tx: mpsc::UnboundedSender<Frame>,
    rx: mpsc::UnboundedReceiver<Bytes>,
    manager: Arc<SessionManager>,

    write_state: WriteState,
    pending_read: Option<Bytes>,
}

impl AnytlsStream {
    pub fn new(
        stream_id: u32,
        tx: mpsc::UnboundedSender<Frame>,
        rx: mpsc::UnboundedReceiver<Bytes>,
        manager: Arc<SessionManager>,
    ) -> Self {
        Self {
            stream_id,
            tx,
            rx,
            manager,
            write_state: WriteState::Init,
            pending_read: None,
        }
    }
}

impl Drop for AnytlsStream {
    fn drop(&mut self) {
        // Send FIN
        let _ = self
            .tx
            .send(Frame::new(CMD_FIN, self.stream_id, Bytes::new()));

        // Remove from manager
        let manager = self.manager.clone();
        let stream_id = self.stream_id;
        tokio::spawn(async move {
            manager.remove_stream(stream_id).await;
        });
    }
}

impl AsyncRead for AnytlsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if let Some(ref mut data) = self.pending_read {
                if !data.is_empty() {
                    let to_read = std::cmp::min(buf.remaining(), data.len());
                    buf.put_slice(&data[..to_read]);
                    data.advance(to_read);
                    return Poll::Ready(Ok(()));
                }
            }

            self.pending_read = None;

            match self.rx.poll_recv(cx) {
                Poll::Ready(Some(data)) => {
                    self.pending_read = Some(data);
                }
                Poll::Ready(None) => return Poll::Ready(Ok(())), // Channel closed
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for AnytlsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let WriteState::Init = self.write_state {
            // First write triggers stream SYN
            let _ = self
                .tx
                .send(Frame::new(CMD_SYN, self.stream_id, Bytes::new()));
            self.write_state = WriteState::TargetWritten;
        }

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let chunk_size = std::cmp::min(buf.len(), 60000);
        let data = Bytes::copy_from_slice(&buf[..chunk_size]);

        if self
            .tx
            .send(Frame::new(CMD_PSH, self.stream_id, data))
            .is_err()
        {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "AnyTLS session closed",
            )));
        }

        Poll::Ready(Ok(chunk_size))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let _ = self
            .tx
            .send(Frame::new(CMD_FIN, self.stream_id, Bytes::new()));
        Poll::Ready(Ok(()))
    }
}
