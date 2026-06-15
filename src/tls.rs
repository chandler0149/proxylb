use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use rustls_pemfile::{certs, ec_private_keys, pkcs8_private_keys, rsa_private_keys};
use tokio_rustls::rustls;
use tokio_rustls::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use tokio_rustls::rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio_rustls::{TlsAcceptor, TlsConnector};

#[derive(Debug)]
struct DummyServerCertVerifier;

impl ServerCertVerifier for DummyServerCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA1,
            rustls::SignatureScheme::ECDSA_SHA1_Legacy,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ED448,
        ]
    }
}

pub fn load_certs<'a>(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let file = File::open(path).with_context(|| format!("failed to open cert file {:?}", path))?;
    let mut reader = BufReader::new(file);
    let certs: Vec<CertificateDer<'static>> = certs(&mut reader)
        .map(|c| c.unwrap().into_owned())
        .collect();
    Ok(certs)
}

pub fn load_private_key<'a>(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let file = File::open(path).with_context(|| format!("failed to open key file {:?}", path))?;
    let mut reader = BufReader::new(file);

    if let Ok(mut keys) = rsa_private_keys(&mut reader).collect::<Result<Vec<_>, _>>() {
        if !keys.is_empty() {
            return Ok(PrivateKeyDer::Pkcs1(keys.remove(0).clone_key()));
        }
    }

    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    if let Ok(mut keys) = pkcs8_private_keys(&mut reader).collect::<Result<Vec<_>, _>>() {
        if !keys.is_empty() {
            return Ok(PrivateKeyDer::Pkcs8(keys.remove(0).clone_key()));
        }
    }

    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    if let Ok(mut keys) = ec_private_keys(&mut reader).collect::<Result<Vec<_>, _>>() {
        if !keys.is_empty() {
            return Ok(PrivateKeyDer::Sec1(keys.remove(0).clone_key()));
        }
    }

    anyhow::bail!("no supported private key found in {:?}", path)
}

pub fn create_tls_acceptor(config: &crate::config::TlsServerConfig) -> Result<TlsAcceptor> {
    match config {
        crate::config::TlsServerConfig::Auto(s) if s == "auto" => {
            let subject_alt_names = vec!["localhost".to_string()];
            let cert = rcgen::generate_simple_self_signed(subject_alt_names)?;
            let cert_der = cert.cert.der().to_vec();
            let key_der = cert.signing_key.serialize_der();

            let rustls_cert = tokio_rustls::rustls::pki_types::CertificateDer::from(cert_der);
            let rustls_key = tokio_rustls::rustls::pki_types::PrivateKeyDer::Pkcs8(
                tokio_rustls::rustls::pki_types::PrivatePkcs8KeyDer::from(key_der),
            );

            let mut server_config = ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(vec![rustls_cert], rustls_key)
                .map_err(|e| anyhow::anyhow!("failed to set auto tls cert: {}", e))?;

            server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

            Ok(TlsAcceptor::from(Arc::new(server_config)))
        }
        crate::config::TlsServerConfig::Auto(s) => {
            anyhow::bail!("invalid tls auto setting: {}", s)
        }
        crate::config::TlsServerConfig::Manual {
            cert: cert_path,
            key: key_path,
        } => {
            let certs = load_certs(Path::new(cert_path))?;
            let key = load_private_key(Path::new(key_path))?;

            let mut server_config = ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs, key)
                .map_err(|e| anyhow::anyhow!("failed to set tls cert: {}", e))?;

            server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

            Ok(TlsAcceptor::from(Arc::new(server_config)))
        }
    }
}

pub fn create_tls_connector(insecure: bool) -> Result<TlsConnector> {
    let mut root_store = RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let config_builder = ClientConfig::builder();

    let config = if insecure {
        config_builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(DummyServerCertVerifier))
            .with_no_client_auth()
    } else {
        config_builder
            .with_root_certificates(root_store)
            .with_no_client_auth()
    };

    Ok(TlsConnector::from(Arc::new(config)))
}

use std::pin::Pin;
use std::task::Poll;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[derive(Debug)]
pub enum MaybeTlsStream<S> {
    Plain(S),
    Tls(tokio_rustls::server::TlsStream<S>),
}

impl<S> AsyncRead for MaybeTlsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            MaybeTlsStream::Plain(s) => Pin::new(s).poll_read(cx, buf),
            MaybeTlsStream::Tls(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl<S> AsyncWrite for MaybeTlsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            MaybeTlsStream::Plain(s) => Pin::new(s).poll_write(cx, buf),
            MaybeTlsStream::Tls(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            MaybeTlsStream::Plain(s) => Pin::new(s).poll_flush(cx),
            MaybeTlsStream::Tls(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            MaybeTlsStream::Plain(s) => Pin::new(s).poll_shutdown(cx),
            MaybeTlsStream::Tls(s) => Pin::new(s).poll_shutdown(cx),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            MaybeTlsStream::Plain(s) => Pin::new(s).poll_write_vectored(cx, bufs),
            MaybeTlsStream::Tls(s) => Pin::new(s).poll_write_vectored(cx, bufs),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match self {
            MaybeTlsStream::Plain(s) => s.is_write_vectored(),
            MaybeTlsStream::Tls(s) => s.is_write_vectored(),
        }
    }
}

#[cfg(target_os = "linux")]
impl<S> crate::relay::AsRawStreamRef for MaybeTlsStream<S>
where
    S: crate::relay::AsRawStreamRef,
{
    fn as_raw_stream_ref(&self) -> Option<crate::relay::RawStreamRef<'_>> {
        match self {
            MaybeTlsStream::Plain(s) => s.as_raw_stream_ref(),
            MaybeTlsStream::Tls(_) => None,
        }
    }
}
