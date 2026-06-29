use crate::outbound::BackendStream;
use bytes::{Bytes, BytesMut};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio_rustls::client::TlsStream;

use super::protocol::*;
use super::stream::AnytlsStream;

use rustc_hash::FxHashMap;

pub enum Control {
    AddStream(u32, mpsc::UnboundedSender<Bytes>),
    RemoveStream(u32),
}

pub struct SessionManager {
    ctrl_tx: mpsc::UnboundedSender<Control>,
    next_stream_id: AtomicU32,
    tx: mpsc::UnboundedSender<Frame>,
    alive: std::sync::atomic::AtomicBool,
}

pub struct Session {
    manager: Arc<SessionManager>,
}

impl Session {
    pub async fn connect(
        password: &str,
        mut tls: TlsStream<BackendStream>,
    ) -> std::io::Result<Self> {
        // 1. Send Auth Request
        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        let hash = hasher.finalize();

        let mut auth_req = Vec::with_capacity(32 + 2);
        auth_req.extend_from_slice(&hash);
        auth_req.extend_from_slice(&0u16.to_be_bytes()); // padding length 0

        tls.write_all(&auth_req).await?;

        // 2. Send cmdSettings
        let settings_data = b"v=2\nclient=proxylb/1.4.1\npadding-md5=";
        let mut settings_frame = BytesMut::new();
        encode_frame_header(
            CMD_SETTINGS,
            0,
            settings_data.len() as u16,
            &mut settings_frame,
        );
        settings_frame.extend_from_slice(settings_data);

        tls.write_all(&settings_frame).await?;
        tls.flush().await?;

        let (mut tls_rx, mut tls_tx) = tokio::io::split(tls);
        let (tx, mut rx) = mpsc::unbounded_channel::<Frame>();

        let (ctrl_tx, mut ctrl_rx) = mpsc::unbounded_channel::<Control>();

        let manager = Arc::new(SessionManager {
            ctrl_tx,
            next_stream_id: AtomicU32::new(1),
            tx: tx.clone(),
            alive: std::sync::atomic::AtomicBool::new(true),
        });

        let manager_writer = manager.clone();
        // Writer Task
        tokio::spawn(async move {
            let mut write_buf = BytesMut::with_capacity(65536);
            while let Some(frame) = rx.recv().await {
                encode_frame_header(
                    frame.cmd,
                    frame.stream_id,
                    frame.data.len() as u16,
                    &mut write_buf,
                );
                if frame.data.len() <= 4096 {
                    write_buf.extend_from_slice(&frame.data);
                } else {
                    if !write_buf.is_empty() {
                        if tls_tx.write_all(&write_buf).await.is_err() {
                            break;
                        }
                        write_buf.clear();
                    }
                    if !frame.data.is_empty() {
                        if tls_tx.write_all(&frame.data).await.is_err() {
                            break;
                        }
                    }
                }

                // Batch writes: flush if channel is empty
                if rx.is_empty() && !write_buf.is_empty() {
                    if tls_tx.write_all(&write_buf).await.is_err() {
                        break;
                    }
                    write_buf.clear();
                }
            }
            manager_writer.alive.store(false, Ordering::Relaxed);
        });

        let manager_clone = manager.clone();

        // Reader Task (Multiplexing Router - Lockless)
        tokio::spawn(async move {
            let mut read_buf = BytesMut::with_capacity(65536);
            let mut streams = FxHashMap::default();

            loop {
                while let Ok(msg) = ctrl_rx.try_recv() {
                    match msg {
                        Control::AddStream(id, tx) => {
                            streams.insert(id, tx);
                        }
                        Control::RemoveStream(id) => {
                            streams.remove(&id);
                        }
                    }
                }

                tokio::select! {
                    biased;
                    msg = ctrl_rx.recv() => {
                        match msg {
                            Some(Control::AddStream(id, tx)) => {
                                streams.insert(id, tx);
                            }
                            Some(Control::RemoveStream(id)) => {
                                streams.remove(&id);
                            }
                            None => break, // SessionManager dropped
                        }
                    }
                    res = tls_rx.read_buf(&mut read_buf) => {
                        match res {
                            Ok(0) => break, // EOF
                            Ok(_) => {
                                // Parse as many frames as possible
                                while let Some(frame) = parse_frame(&mut read_buf) {
                                    match frame.cmd {
                                        CMD_PSH => {
                                            if let Some(sender) = streams.get(&frame.stream_id) {
                                                let _ = sender.send(frame.data);
                                            }
                                        }
                                        CMD_FIN => {
                                            streams.remove(&frame.stream_id);
                                        }
                                        CMD_HEART_REQUEST => {
                                            let _ = tx.send(Frame::new(CMD_HEART_RESPONSE, 0, Bytes::new()));
                                        }
                                        CMD_ALERT => {
                                            tracing::error!(
                                                "AnyTLS Alert: {}",
                                                String::from_utf8_lossy(&frame.data)
                                            );
                                            // Fatal, close session
                                            manager_clone.alive.store(false, Ordering::Relaxed);
                                            return;
                                        }
                                        CMD_SYNACK => {
                                            if !frame.data.is_empty() {
                                                tracing::warn!(
                                                    "AnyTLS stream {} failed: {}",
                                                    frame.stream_id,
                                                    String::from_utf8_lossy(&frame.data)
                                                );
                                                streams.remove(&frame.stream_id);
                                            }
                                        }
                                        _ => {
                                            // Ignore CMD_SERVER_SETTINGS, CMD_UPDATE_PADDING_SCHEME, CMD_WASTE
                                        }
                                    }
                                }
                            }
                            Err(_) => break, // Error
                        }
                    }
                }
            }
            manager_clone.alive.store(false, Ordering::Relaxed);
        });

        Ok(Self { manager })
    }

    pub async fn open_stream(&self) -> AnytlsStream {
        let stream_id = self.manager.next_stream_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = mpsc::unbounded_channel();

        let _ = self.manager.ctrl_tx.send(Control::AddStream(stream_id, tx));

        AnytlsStream::new(stream_id, self.manager.tx.clone(), rx, self.manager.clone())
    }

    pub fn is_alive(&self) -> bool {
        self.manager.alive.load(Ordering::Relaxed)
    }
}

impl SessionManager {
    pub async fn remove_stream(&self, stream_id: u32) {
        let _ = self.ctrl_tx.send(Control::RemoveStream(stream_id));
    }
}
