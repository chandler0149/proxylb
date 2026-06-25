use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio_util::sync::CancellationToken;

use super::BoundListener;
use crate::backend::BackendPool;
use crate::outbound::TargetAddr;

use mtproto_server::protocol::constants::{self, *};
use mtproto_server::handshake::*;
use mtproto_server::stream::{FakeTlsReader, FakeTlsWriter, CryptoReader, CryptoWriter};
use mtproto_server::protocol::tls;
use mtproto_server::crypto::{SecureRandom, AesCtr};

pub async fn run_mtproto_inbound(
    listen_addr: String,
    pool: BackendPool,
    stats: Arc<crate::backend::InboundStats>,
    local_filter_manager: Option<Arc<crate::filter::FilterManager>>,
    secret_hex: String,
    _tls_cfg: Option<crate::config::TlsServerConfig>,
    route_idx: Option<usize>,
    cancel: CancellationToken,
    prebound_uds: Option<std::os::unix::net::UnixListener>,
) -> anyhow::Result<()> {
    let mut secret = [0u8; MTPROTO_SECRET_BYTES];
    let decoded = (0..secret_hex.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(&secret_hex[i..i + 2], 16).ok())
        .collect::<Vec<u8>>();
    if decoded.len() == MTPROTO_SECRET_BYTES {
        secret.copy_from_slice(&decoded);
    } else {
        anyhow::bail!("Invalid mtproto secret length, must be 32 hex chars");
    }

    let listener = BoundListener::bind(&listen_addr, prebound_uds).await?;
    tracing::info!(listen = %listen_addr, "MTProto inbound listener started");

    crate::inbound::run_accept_loop(listener, cancel, "MTProto", move |stream, addr| {
        let pool = pool.clone();
        let stats = Arc::clone(&stats);
        let secret = secret.clone();
        let local_filter_manager = local_filter_manager.clone();

        async move {
            if let Err(e) = handle_mtproto_connection(
                stream,
                pool,
                stats,
                local_filter_manager.clone(),
                secret,
                SecureRandom::new(),
                route_idx,
            )
            .await
            {
                tracing::debug!(client = %addr, error = %e, "MTProto connection failed");
            }
        }
    })
    .await
}

struct PeekStream<S> {
    inner: S,
    peek_buf: Vec<u8>,
    peek_pos: usize,
}

impl<S> PeekStream<S> {
    fn new(inner: S, peek_buf: Vec<u8>) -> Self {
        Self {
            inner,
            peek_buf,
            peek_pos: 0,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PeekStream<S> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if self.peek_pos < self.peek_buf.len() {
            let remaining = self.peek_buf.len() - self.peek_pos;
            let to_read = std::cmp::min(remaining, buf.remaining());
            buf.put_slice(&self.peek_buf[self.peek_pos..self.peek_pos + to_read]);
            self.peek_pos += to_read;
            std::task::Poll::Ready(Ok(()))
        } else {
            std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PeekStream<S> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(target_os = "linux")]
impl<S: crate::relay::AsRawStreamRef> crate::relay::AsRawStreamRef for PeekStream<S> {
    #[cfg(target_os = "linux")]
    fn as_raw_stream_ref(&self) -> Option<crate::relay::RawStreamRef<'_>> {
        self.inner.as_raw_stream_ref()
    }

    #[cfg(target_os = "linux")]
    fn take_preallocated_pipes(&mut self) -> Option<crate::relay::PreallocatedPipes> {
        self.inner.take_preallocated_pipes()
    }
}

async fn handle_mtproto_connection<S>(
    mut stream: S,
    pool: BackendPool,
    stats: Arc<crate::backend::InboundStats>,
    local_filter_manager: Option<Arc<crate::filter::FilterManager>>,
    secret: [u8; MTPROTO_SECRET_BYTES],
    rng: SecureRandom,
    route_idx: Option<usize>,
) -> anyhow::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + crate::relay::AsRawStreamRef + 'static,
{
    // Apply TLS if configured.
    // Wait, MTProto handles its own FakeTLS, but if standard TLS is configured...
    // Usually MTProto is used directly. We'll support both.
    
    let mut peek_buf = [0u8; 1024];
    let mut peek_len = 0;
    while peek_len < 64 {
        let n = stream.read(&mut peek_buf[peek_len..]).await?;
        if n == 0 {
            anyhow::bail!("EOF before handshake");
        }
        peek_len += n;
    }

    let is_tls = tls::is_tls_handshake(&peek_buf);
    let mut matched_tls_validation = None;

    let mut total_hello_len = 0;

    if is_tls {
        let tls_len = ((peek_buf[3] as usize) << 8) | (peek_buf[4] as usize);
        total_hello_len = 5 + tls_len;
        
        if total_hello_len > peek_buf.len() {
            anyhow::bail!("TLS ClientHello too large: {}", total_hello_len);
        }

        while peek_len < total_hello_len {
            let n = stream.read(&mut peek_buf[peek_len..total_hello_len]).await?;
            if n == 0 {
                anyhow::bail!("EOF before full ClientHello");
            }
            peek_len += n;
        }

        if let Some(parsed) = parse_tls_auth_material(&peek_buf[..peek_len], true, 300) {
            if let Some(validation) = validate_tls_secret_candidate(&parsed, &peek_buf[..peek_len], &secret) {
                matched_tls_validation = Some(validation);
            }
        }

        if matched_tls_validation.is_none() {
            // It looked like TLS, but validation failed. We reject it instead of falling back to Plain MTProto
            anyhow::bail!("Invalid FakeTLS handshake");
        }
    }

    if let Some(validation) = matched_tls_validation {
        // Fake TLS handshake
        let server_hello = tls::build_server_hello(
            &secret,
            &validation.digest,
            &validation.session_id[..validation.session_id_len.min(validation.session_id.len())],
            3000,
            &rng,
            None,
            1,
        );
        stream.write_all(&server_hello).await?;

        let peek_stream = PeekStream::new(stream, peek_buf[total_hello_len..peek_len].to_vec());
        let (read_half, write_half) = tokio::io::split(peek_stream);
        let mut fake_tls_reader = FakeTlsReader::new(read_half);
        let fake_tls_writer = FakeTlsWriter::new(write_half);
        
        let handshake_bytes = fake_tls_reader.read_exact(HANDSHAKE_LEN).await.map_err(|e| anyhow::anyhow!("FakeTLS read exact failed: {:?}", e))?;
        let mut handshake = [0u8; HANDSHAKE_LEN];
        handshake.copy_from_slice(&handshake_bytes);

        let (backend_stream, chosen_traffic, target_addr, validation) = connect_and_proxy(
            &handshake, secret, pool, stats.clone(), local_filter_manager.clone(), true, route_idx
        ).await?;

        let client_combined = CombinedStream::new(
            CryptoReader::new(fake_tls_reader, validation.decryptor),
            CryptoWriter::new(fake_tls_writer, validation.encryptor, 65536),
        );

        crate::inbound::relay_and_track(
            client_combined,
            backend_stream,
            chosen_traffic,
            Some(stats),
            &target_addr,
            "MTProto",
        ).await
    } else {
        // Plain MTProto handshake
        if peek_len < HANDSHAKE_LEN {
            let mut remaining = HANDSHAKE_LEN - peek_len;
            while remaining > 0 {
                let n = stream.read(&mut peek_buf[peek_len..peek_len+remaining]).await?;
                if n == 0 { anyhow::bail!("EOF reading handshake"); }
                peek_len += n;
                remaining -= n;
            }
        }
        let mut handshake = [0u8; HANDSHAKE_LEN];
        handshake.copy_from_slice(&peek_buf[..HANDSHAKE_LEN]);

        let (backend_stream, chosen_traffic, target_addr, validation) = connect_and_proxy(
            &handshake, secret, pool, stats.clone(), local_filter_manager.clone(), false, route_idx
        ).await?;

        let peek_stream = PeekStream::new(stream, peek_buf[HANDSHAKE_LEN..peek_len].to_vec());
        let (read_half, write_half) = tokio::io::split(peek_stream);
        let client_combined = CombinedStream::new(
            CryptoReader::new(read_half, validation.decryptor),
            CryptoWriter::new(write_half, validation.encryptor, 65536),
        );

        crate::inbound::relay_and_track(
            client_combined,
            backend_stream,
            chosen_traffic,
            Some(stats),
            &target_addr,
            "MTProto",
        ).await
    }
}

async fn connect_and_proxy(
    handshake: &[u8; HANDSHAKE_LEN],
    secret: [u8; MTPROTO_SECRET_BYTES],
    pool: BackendPool,
    _stats: Arc<crate::backend::InboundStats>,
    local_filter_manager: Option<Arc<crate::filter::FilterManager>>,
    _is_tls: bool,
    route_idx: Option<usize>,
) -> anyhow::Result<(
    crate::outbound::BackendStream,
    std::sync::Arc<crate::backend::TrafficCounters>,
    TargetAddr,
    mtproto_server::handshake::MtprotoCandidateValidation,
)> {
    let mut dec_prekey = [0u8; PREKEY_LEN];
    let mut dec_iv_arr = [0u8; IV_LEN];
    let mut enc_prekey = [0u8; PREKEY_LEN];
    let mut enc_iv_arr = [0u8; IV_LEN];

    const SKIP_LEN: usize = 8;
    
    dec_prekey.copy_from_slice(&handshake[SKIP_LEN..SKIP_LEN + PREKEY_LEN]);
    dec_iv_arr.copy_from_slice(&handshake[SKIP_LEN + PREKEY_LEN..SKIP_LEN + PREKEY_LEN + IV_LEN]);
    let dec_iv = u128::from_be_bytes(dec_iv_arr);

    let dec_prekey_iv = &handshake[SKIP_LEN..SKIP_LEN + PREKEY_LEN + IV_LEN];
    let enc_prekey_iv: Vec<u8> = dec_prekey_iv.iter().rev().copied().collect();
    
    enc_prekey.copy_from_slice(&enc_prekey_iv[..PREKEY_LEN]);
    enc_iv_arr.copy_from_slice(&enc_prekey_iv[PREKEY_LEN..PREKEY_LEN + IV_LEN]);
    let enc_iv = u128::from_be_bytes(enc_iv_arr);

    let validation = validate_mtproto_secret_candidate(
        handshake,
        &dec_prekey,
        dec_iv,
        &enc_prekey,
        enc_iv,
        &secret,
    ).ok_or_else(|| anyhow::anyhow!("Invalid MTProto handshake"))?;

    let dc_idx = validation.dc_idx.abs();
    
    // Map DC index to IP using canonical Telegram datacenter addresses.
    let dc_array_idx = (dc_idx as usize).saturating_sub(1).min(constants::TG_DATACENTERS_V4.len() - 1);
    let ip = constants::TG_DATACENTERS_V4[dc_array_idx];

    let target_addr = TargetAddr::Ip(std::net::SocketAddr::new(
        ip,
        443,
    ));

    tracing::debug!(dc = %dc_idx, target = %target_addr, "MTProto connection matched");

    let is_blocked = if let Some(ref m) = local_filter_manager {
        m.is_blocked(&target_addr)
    } else {
        pool.filter_manager.is_blocked(&target_addr)
    };

    if is_blocked {
        anyhow::bail!("MTProto connection blocked by filter");
    }

    let (mut backend_stream, chosen_traffic) = crate::inbound::route_and_connect(&pool, &target_addr, route_idx).await?;
    
    let (nonce, tg_encryptor, tg_decryptor) = generate_and_encrypt_tg_nonce(
        validation.proto_tag,
        validation.dc_idx,
        &mut mtproto_server::crypto::SecureRandom::new(),
    );

    backend_stream.write_all(&nonce).await?;

    let (read_half, write_half) = tokio::io::split(backend_stream);
    let tg_reader = CryptoReader::new(read_half, tg_decryptor);
    let tg_writer = CryptoWriter::new(write_half, tg_encryptor, 65536);

    let wrapped_backend = crate::outbound::BackendStream::boxed(Box::pin(CombinedStream::new(tg_reader, tg_writer)));

    Ok((wrapped_backend, chosen_traffic, target_addr, validation))
}

fn generate_and_encrypt_tg_nonce(
    proto_tag: mtproto_server::protocol::ProtoTag,
    dc_idx: i16,
    rng: &mut mtproto_server::crypto::SecureRandom,
) -> (Vec<u8>, AesCtr, AesCtr) {
    use mtproto_server::protocol::constants::{SKIP_LEN, PROTO_TAG_POS, DC_IDX_POS};
    
    let mut nonce = [0u8; HANDSHAKE_LEN];
    loop {
        let bytes = rng.bytes(HANDSHAKE_LEN);
        nonce.copy_from_slice(&bytes[..HANDSHAKE_LEN]);
        if mtproto_server::protocol::obfuscation::is_valid_nonce(&nonce) {
            break;
        }
    }
    nonce[PROTO_TAG_POS..PROTO_TAG_POS + 4].copy_from_slice(&proto_tag.to_bytes());
    nonce[DC_IDX_POS..DC_IDX_POS + 2].copy_from_slice(&dc_idx.to_le_bytes());

    let enc_key_iv = &nonce[SKIP_LEN..SKIP_LEN + KEY_LEN + IV_LEN];
    let dec_key_iv: Vec<u8> = enc_key_iv.iter().rev().copied().collect();

    let mut enc_key = [0u8; 32];
    enc_key.copy_from_slice(&enc_key_iv[..KEY_LEN]);
    let mut enc_iv_arr = [0u8; IV_LEN];
    enc_iv_arr.copy_from_slice(&enc_key_iv[KEY_LEN..]);
    let enc_iv = u128::from_be_bytes(enc_iv_arr);

    let mut dec_key = [0u8; 32];
    dec_key.copy_from_slice(&dec_key_iv[..KEY_LEN]);
    let mut dec_iv_arr = [0u8; IV_LEN];
    dec_iv_arr.copy_from_slice(&dec_key_iv[KEY_LEN..]);
    let dec_iv = u128::from_be_bytes(dec_iv_arr);

    let mut encryptor = AesCtr::new(&enc_key, enc_iv);
    let encrypted_full = encryptor.encrypt(&nonce);

    let mut result = nonce[..PROTO_TAG_POS].to_vec();
    result.extend_from_slice(&encrypted_full[PROTO_TAG_POS..]);

    let decryptor = AesCtr::new(&dec_key, dec_iv);

    (result, encryptor, decryptor)
}

// Dummy CombinedStream for testing compilation
struct CombinedStream<R, W> {
    reader: R,
    writer: W,
}

impl<R, W> CombinedStream<R, W> {
    fn new(reader: R, writer: W) -> Self {
        Self { reader, writer }
    }
}

impl<R: AsyncRead + Unpin, W: Unpin> AsyncRead for CombinedStream<R, W> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.reader).poll_read(cx, buf)
    }
}

impl<R: Unpin, W: AsyncWrite + Unpin> AsyncWrite for CombinedStream<R, W> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.writer).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.writer).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        // Flush the entire write chain before initiating shutdown
        match std::pin::Pin::new(&mut self.writer).poll_flush(cx) {
            std::task::Poll::Pending => return std::task::Poll::Pending,
            std::task::Poll::Ready(Err(e)) => return std::task::Poll::Ready(Err(e)),
            std::task::Poll::Ready(Ok(())) => {}
        }
        std::pin::Pin::new(&mut self.writer).poll_shutdown(cx)
    }
}

#[cfg(target_os = "linux")]
impl<R, W> crate::relay::AsRawStreamRef for CombinedStream<R, W> {
    #[cfg(target_os = "linux")]
    fn as_raw_stream_ref(&self) -> Option<crate::relay::RawStreamRef<'_>> {
        None
    }

    #[cfg(target_os = "linux")]
    fn take_preallocated_pipes(&mut self) -> Option<crate::relay::PreallocatedPipes> {
        None
    }
}
