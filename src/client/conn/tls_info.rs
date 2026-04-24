use bytes::Bytes;
use tokio::net::TcpStream;
#[cfg(unix)]
use tokio::net::UnixStream;
use tokio_boring2::SslStream;

use crate::tls::conn::{
    captured_chain_der_from_ssl, encrypted_extensions_index, server_hello_index,
};
use crate::tls::{TlsInfo, conn::MaybeHttpsStream};

/// A trait for extracting TLS information from a connection.
///
/// Implementors can provide access to peer certificate data or other TLS-related metadata.
/// For non-TLS connections, this typically returns `None`.
pub trait TlsInfoFactory {
    fn tls_info(&self) -> Option<TlsInfo>;
}

fn extract_tls_info<S>(ssl_stream: &SslStream<S>) -> TlsInfo {
    let ssl = ssl_stream.ssl();
    let captured_chain_der =
        captured_chain_der_from_ssl(ssl).map(|chain| chain.into_iter().map(Bytes::from).collect());
    let peer_certificate = ssl
        .peer_certificate()
        .and_then(|cert| cert.to_der().ok())
        .map(Bytes::from)
        .or_else(|| {
            captured_chain_der
                .as_ref()
                .and_then(|chain: &Vec<Bytes>| chain.first().cloned())
        });
    TlsInfo {
        peer_certificate,
        // Prefer the handshake-message-captured chain over peer_cert_chain()
        // because BoringSSL does not always populate peer_cert_chain() when
        // verification is disabled.
        peer_certificate_chain: captured_chain_der.clone().or_else(|| {
            ssl.peer_cert_chain().map(|chain| {
                chain
                    .iter()
                    .filter_map(|cert| cert.to_der().ok())
                    .map(Bytes::from)
                    .collect()
            })
        }),
        captured_chain_der,
        server_hello: server_hello_index()
            .ok()
            .and_then(|idx| ssl.ex_data(idx).cloned())
            .map(Bytes::from),
        encrypted_extensions: encrypted_extensions_index()
            .ok()
            .and_then(|idx| ssl.ex_data(idx).cloned())
            .map(Bytes::from),
    }
}

// ===== impl TcpStream =====

impl TlsInfoFactory for TcpStream {
    fn tls_info(&self) -> Option<TlsInfo> {
        None
    }
}

impl TlsInfoFactory for SslStream<TcpStream> {
    #[inline]
    fn tls_info(&self) -> Option<TlsInfo> {
        Some(extract_tls_info(self))
    }
}

impl TlsInfoFactory for MaybeHttpsStream<TcpStream> {
    fn tls_info(&self) -> Option<TlsInfo> {
        match self {
            MaybeHttpsStream::Https(tls) => tls.tls_info(),
            MaybeHttpsStream::Http(_) => None,
        }
    }
}

impl TlsInfoFactory for SslStream<MaybeHttpsStream<TcpStream>> {
    #[inline]
    fn tls_info(&self) -> Option<TlsInfo> {
        Some(extract_tls_info(self))
    }
}

// ===== impl UnixStream =====

#[cfg(unix)]
impl TlsInfoFactory for UnixStream {
    fn tls_info(&self) -> Option<TlsInfo> {
        None
    }
}

#[cfg(unix)]
impl TlsInfoFactory for SslStream<UnixStream> {
    #[inline]
    fn tls_info(&self) -> Option<TlsInfo> {
        Some(extract_tls_info(self))
    }
}

#[cfg(unix)]
impl TlsInfoFactory for MaybeHttpsStream<UnixStream> {
    fn tls_info(&self) -> Option<TlsInfo> {
        match self {
            MaybeHttpsStream::Https(tls) => tls.tls_info(),
            MaybeHttpsStream::Http(_) => None,
        }
    }
}

#[cfg(unix)]
impl TlsInfoFactory for SslStream<MaybeHttpsStream<UnixStream>> {
    #[inline]
    fn tls_info(&self) -> Option<TlsInfo> {
        Some(extract_tls_info(self))
    }
}
