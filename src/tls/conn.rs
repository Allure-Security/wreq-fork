//! SSL support via BoringSSL.

#[macro_use]
mod macros;
mod ext;
mod service;

use std::{
    borrow::Cow,
    fmt::{self, Debug},
    io,
    pin::Pin,
    sync::{Arc, LazyLock},
    task::{Context, Poll},
};

use btls::{
    error::ErrorStack,
    ex_data::Index,
    ssl::{Ssl, SslConnector, SslMethod, SslOptions, SslSessionCacheMode},
};
use btls_sys as ffi;
use ext::SslConnectorBuilderExt;
use http::{Uri, Version};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_btls::SslStream;
use tower::{BoxError, Service};

use crate::{
    Error,
    conn::{Connected, Connection, descriptor::ConnectionDescriptor},
    tls::{
        AlpnProtocol, AlpsProtocol, KeyShare, TlsOptions, TlsVersion,
        keylog::KeyLog,
        session::{Key, LruTlsSessionCache, TlsSession, TlsSessionCache},
        trust::{CertStore, Identity},
    },
};

// ── ServerHello + captured-chain capture ─────────────────────────────
// TLS capture state lives on the Ssl itself via ex_data so the
// extract path (tls_info.rs) reads them regardless of which thread is
// polling the task. An earlier version used thread-locals and raced with
// tokio task migration: the handshake thread would write the ServerHello
// bytes, then the extract ran on a different thread after an .await and
// saw None. That showed up as ja4s being missing on a random subset of
// scans, notably on bad-cert hosts whose handshake completes but yields
// no ja4s.

pub(crate) fn server_hello_index() -> Result<Index<Ssl, Vec<u8>>, ErrorStack> {
    static IDX: LazyLock<Result<Index<Ssl, Vec<u8>>, ErrorStack>> =
        LazyLock::new(Ssl::new_ex_index);
    IDX.clone()
}

pub(crate) fn encrypted_extensions_index() -> Result<Index<Ssl, Vec<u8>>, ErrorStack> {
    static IDX: LazyLock<Result<Index<Ssl, Vec<u8>>, ErrorStack>> =
        LazyLock::new(Ssl::new_ex_index);
    IDX.clone()
}

/// ex_data index for the captured certificate chain DER bytes.
///
/// The chain may be verifier-built or verifier-observed depending on the
/// handshake outcome, so do not call it "verified" here. MarcoPolo validates
/// this DER post-handshake against the scan hostname.
type CapturedChainIndex = Result<Index<Ssl, Vec<Vec<u8>>>, ErrorStack>;

pub(crate) fn captured_chain_der_index() -> CapturedChainIndex {
    static IDX: LazyLock<CapturedChainIndex> = LazyLock::new(Ssl::new_ex_index);
    IDX.clone()
}

pub(crate) fn captured_chain_der_from_ssl(ssl: &btls::ssl::SslRef) -> Option<Vec<Vec<u8>>> {
    captured_chain_der_index()
        .ok()
        .and_then(|idx| ssl.ex_data(idx).cloned())
}

fn read_u24(input: &[u8]) -> Option<usize> {
    if input.len() < 3 {
        return None;
    }
    Some(((input[0] as usize) << 16) | ((input[1] as usize) << 8) | input[2] as usize)
}

fn parse_tls12_certificate_list(body: &[u8]) -> Option<Vec<Vec<u8>>> {
    let list_len = read_u24(body)?;
    let list_start = 3usize;
    let list_end = list_start.checked_add(list_len)?;
    if list_end != body.len() {
        return None;
    }

    let mut pos = list_start;
    let mut chain = Vec::new();
    while pos < list_end {
        let cert_len = read_u24(body.get(pos..pos + 3)?)?;
        pos = pos.checked_add(3)?;
        let cert_end = pos.checked_add(cert_len)?;
        if cert_end > list_end {
            return None;
        }
        chain.push(body[pos..cert_end].to_vec());
        pos = cert_end;
    }

    if chain.is_empty() { None } else { Some(chain) }
}

fn parse_tls13_certificate_list(body: &[u8]) -> Option<Vec<Vec<u8>>> {
    let context_len = *body.first()? as usize;
    let mut pos = 1usize.checked_add(context_len)?;
    if pos + 3 > body.len() {
        return None;
    }

    let list_len = read_u24(&body[pos..pos + 3])?;
    pos = pos.checked_add(3)?;
    let list_end = pos.checked_add(list_len)?;
    if list_end != body.len() {
        return None;
    }

    let mut chain = Vec::new();
    while pos < list_end {
        if pos + 3 > list_end {
            return None;
        }
        let cert_len = read_u24(&body[pos..pos + 3])?;
        pos = pos.checked_add(3)?;
        let cert_end = pos.checked_add(cert_len)?;
        let ext_len_pos_end = cert_end.checked_add(2)?;
        if ext_len_pos_end > list_end {
            return None;
        }
        chain.push(body[pos..cert_end].to_vec());
        pos = cert_end;

        let ext_len = ((body[pos] as usize) << 8) | body[pos + 1] as usize;
        pos = pos.checked_add(2)?;
        let ext_end = pos.checked_add(ext_len)?;
        if ext_end > list_end {
            return None;
        }
        pos = ext_end;
    }

    if chain.is_empty() { None } else { Some(chain) }
}

fn parse_certificate_message_der(data: &[u8]) -> Option<Vec<Vec<u8>>> {
    if data.len() < 4 || data[0] != 0x0b {
        return None;
    }

    let body_len = read_u24(&data[1..4])?;
    let body_end = 4usize.checked_add(body_len)?;
    if body_end != data.len() {
        return None;
    }

    let body = &data[4..];
    parse_tls13_certificate_list(body).or_else(|| parse_tls12_certificate_list(body))
}

#[allow(unsafe_code)]
fn store_captured_chain_der(ssl: *mut ffi::SSL, chain: Vec<Vec<u8>>) {
    if chain.is_empty() {
        return;
    }
    // Safety: BoringSSL passes a valid SSL pointer for the duration of this
    // callback. Nothing else aliases it while we are synchronously inside
    // SSL_do_handshake.
    let ssl_ref = unsafe { &mut *(ssl as *mut btls::ssl::SslRef) };
    if let Ok(idx) = captured_chain_der_index() {
        ssl_ref.set_ex_data(idx, chain);
    }
}

/// Raw C callback for SSL_CTX_set_msg_callback.
/// content_type=22 is Handshake. buf starts with handshake type byte:
/// 0x02 = ServerHello, 0x08 = EncryptedExtensions, 0x0b = Certificate.
#[allow(unsafe_code, unsafe_op_in_unsafe_fn)]
unsafe extern "C" fn server_hello_msg_callback(
    is_write: std::os::raw::c_int,
    _version: std::os::raw::c_int,
    content_type: std::os::raw::c_int,
    buf: *const std::os::raw::c_void,
    len: usize,
    ssl: *mut ffi::SSL,
    _arg: *mut std::os::raw::c_void,
) {
    if is_write != 0 || content_type != 22 || len < 4 {
        return;
    }
    let data = unsafe { std::slice::from_raw_parts(buf as *const u8, len) };
    if data[0] == 0x02 {
        let hello_body: Vec<u8> = if len > 4 {
            data[4..].to_vec()
        } else {
            data.to_vec()
        };
        // Safety: BoringSSL passes a valid SSL pointer for the duration of
        // this callback. Nothing else aliases it while we are synchronously
        // inside SSL_do_handshake.
        // btls::ssl::SslRef is a transparent wrapper around ffi::SSL,
        // so a pointer cast gives us the same &mut SslRef that
        // ForeignTypeRef::from_ptr_mut would, without pulling in
        // foreign_types as a direct dependency.
        let ssl_ref = unsafe { &mut *(ssl as *mut btls::ssl::SslRef) };
        if let Ok(idx) = server_hello_index() {
            ssl_ref.set_ex_data(idx, hello_body);
        }
    } else if data[0] == 0x08 {
        let ee_body: Vec<u8> = if len > 4 {
            data[4..].to_vec()
        } else {
            data.to_vec()
        };
        let ssl_ref = unsafe { &mut *(ssl as *mut btls::ssl::SslRef) };
        if let Ok(idx) = encrypted_extensions_index() {
            ssl_ref.set_ex_data(idx, ee_body);
        }
    } else if data[0] == 0x0b
        && let Some(chain) = parse_certificate_message_der(data)
    {
        store_captured_chain_der(ssl, chain);
    }
}

#[cfg(test)]
mod cert_message_tests {
    use super::parse_certificate_message_der;

    fn push_u24(out: &mut Vec<u8>, value: usize) {
        out.push(((value >> 16) & 0xff) as u8);
        out.push(((value >> 8) & 0xff) as u8);
        out.push((value & 0xff) as u8);
    }

    fn handshake(mut body: Vec<u8>) -> Vec<u8> {
        let mut out = vec![0x0b];
        push_u24(&mut out, body.len());
        out.append(&mut body);
        out
    }

    #[test]
    fn parses_tls12_certificate_message() {
        let leaf = vec![0x30, 0x82, 0x01, 0x02];
        let intermediate = vec![0x30, 0x82, 0x03];
        let mut list = Vec::new();
        push_u24(&mut list, leaf.len());
        list.extend_from_slice(&leaf);
        push_u24(&mut list, intermediate.len());
        list.extend_from_slice(&intermediate);

        let mut body = Vec::new();
        push_u24(&mut body, list.len());
        body.extend_from_slice(&list);

        let parsed = parse_certificate_message_der(&handshake(body)).unwrap();
        assert_eq!(parsed, vec![leaf, intermediate]);
    }

    #[test]
    fn parses_tls13_certificate_message_with_extensions() {
        let leaf = vec![0x30, 0x82, 0x05];
        let mut list = Vec::new();
        push_u24(&mut list, leaf.len());
        list.extend_from_slice(&leaf);
        list.extend_from_slice(&[0x00, 0x02, 0xaa, 0xbb]);

        let mut body = vec![0x00];
        push_u24(&mut body, list.len());
        body.extend_from_slice(&list);

        let parsed = parse_certificate_message_der(&handshake(body)).unwrap();
        assert_eq!(parsed, vec![leaf]);
    }

    #[test]
    fn rejects_truncated_certificate_message() {
        let mut data = handshake(vec![0x00, 0x00, 0x04, 0x00, 0x00, 0x03, 0x30]);
        data.pop();
        assert!(parse_certificate_message_der(&data).is_none());
    }
}

fn key_index() -> Result<Index<Ssl, Key>, ErrorStack> {
    static IDX: LazyLock<Result<Index<Ssl, Key>, ErrorStack>> = LazyLock::new(Ssl::new_ex_index);
    IDX.clone()
}

/// Settings for [`TlsConnector`]
#[derive(Clone)]
pub struct HandshakeSettings {
    no_ticket: bool,
    enable_ech_grease: bool,
    verify_hostname: bool,
    tls_sni: bool,
    alpn_protocols: Option<Cow<'static, [AlpnProtocol]>>,
    alps_protocols: Option<Cow<'static, [AlpsProtocol]>>,
    alps_use_new_codepoint: bool,
    key_shares: Option<Cow<'static, [KeyShare]>>,
    random_aes_hw_override: bool,
}

/// A Connector using BoringSSL to support `http` and `https` schemes.
#[derive(Clone)]
pub struct HttpsConnector<T> {
    http: T,
    tls: TlsConnector,
}

/// A builder for creating a `TlsConnector`.
pub struct TlsConnectorBuilder {
    alpn_protocol: Option<AlpnProtocol>,
    max_version: Option<TlsVersion>,
    min_version: Option<TlsVersion>,
    tls_sni: bool,
    verify_hostname: bool,
    identity: Option<Identity>,
    cert_store: Option<CertStore>,
    cert_verification: bool,
    keylog: Option<KeyLog>,
    session_cache: Arc<dyn TlsSessionCache>,
}

/// A layer which wraps services in an `SslConnector`.
#[derive(Clone)]
pub struct TlsConnector {
    ssl: SslConnector,
    cache: Option<Arc<dyn TlsSessionCache>>,
    settings: HandshakeSettings,
}

// ===== impl HttpsConnector =====

impl<S, T> HttpsConnector<S>
where
    S: Service<Uri, Response = T> + Send,
    S::Error: Into<BoxError>,
    S::Future: Unpin + Send + 'static,
    T: AsyncRead + AsyncWrite + Connection + Unpin + Debug + Sync + Send + 'static,
{
    /// Creates a new [`HttpsConnector`] with a given [`TlsConnector`].
    #[inline]
    pub fn new(http: S, tls: TlsConnector) -> HttpsConnector<S> {
        HttpsConnector { http, tls }
    }

    /// Disables ALPN negotiation.
    #[inline]
    pub fn no_alpn(&mut self) -> &mut Self {
        self.tls.settings.alpn_protocols = None;
        self
    }
}

// ===== impl TlsConnector =====

impl TlsConnector {
    /// Creates a new [`TlsConnectorBuilder`] with the given configuration.
    pub fn builder() -> TlsConnectorBuilder {
        TlsConnectorBuilder {
            alpn_protocol: None,
            min_version: None,
            max_version: None,
            identity: None,
            tls_sni: true,
            verify_hostname: true,
            cert_store: None,
            cert_verification: true,
            keylog: None,
            session_cache: Arc::new(LruTlsSessionCache::new(8)),
        }
    }

    fn setup_ssl(&self, uri: Uri) -> Result<Ssl, BoxError> {
        let cfg = self.ssl.configure()?;
        let host = uri.host().ok_or("URI missing host")?;
        let host = Self::normalize_host(host);
        let ssl = cfg.into_ssl(host)?;
        Ok(ssl)
    }

    fn setup_ssl2(&self, descriptor: ConnectionDescriptor) -> Result<Ssl, BoxError> {
        let mut cfg = self.ssl.configure()?;

        // Use server name indication
        cfg.set_use_server_name_indication(self.settings.tls_sni);

        // Verify hostname
        cfg.set_verify_hostname(self.settings.verify_hostname);

        // Set ECH grease
        cfg.set_enable_ech_grease(self.settings.enable_ech_grease);

        // Set random AES hardware override
        if self.settings.random_aes_hw_override {
            let random = (crate::util::fast_random() & 1) == 0;
            cfg.set_aes_hw_override(random);
        }

        // Set ALPN protocols
        if let Some(version) = descriptor.version() {
            match version {
                Version::HTTP_11 | Version::HTTP_10 | Version::HTTP_09 => {
                    cfg.set_alpn_protos(&AlpnProtocol::HTTP1.encode())?;
                }
                Version::HTTP_2 => {
                    cfg.set_alpn_protos(&AlpnProtocol::HTTP2.encode())?;
                }
                Version::HTTP_3 => {
                    cfg.set_alpn_protos(&AlpnProtocol::HTTP3.encode())?;
                }
                _ => {
                    // For unknown versions, we don't set any ALPN protocols.
                }
            }
        } else {
            // Default use the connector configuration.
            if let Some(ref alpn_values) = self.settings.alpn_protocols {
                let encoded = AlpnProtocol::encode_sequence(alpn_values.as_ref());
                cfg.set_alpn_protos(&encoded)?;
            }
        }

        // Set ALPS protos
        if let Some(ref alps_values) = self.settings.alps_protocols {
            for alps in alps_values.iter() {
                cfg.add_application_settings(alps.0)?;
            }

            // By default, the new endpoint is used.
            if !alps_values.is_empty() {
                cfg.set_alps_use_new_codepoint(self.settings.alps_use_new_codepoint);
            }
        }

        // Set TLS key shares
        if let Some(ref key_shares) = self.settings.key_shares {
            cfg.set_client_key_shares(key_shares.as_ref())?;
        }

        let uri = descriptor.uri().clone();
        let host = uri.host().ok_or("URI missing host")?;
        let host = Self::normalize_host(host);

        if let Some(ref cache) = self.cache {
            let key = Key(descriptor.id());

            // If the session cache is enabled, we try to retrieve the session
            // associated with the key. If it exists, we set it in the SSL configuration.
            if let Some(session) = cache.pop(&key) {
                #[allow(unsafe_code)]
                unsafe { cfg.set_session(&session.0) }?;

                if self.settings.no_ticket {
                    cfg.set_options(SslOptions::NO_TICKET);
                }
            }

            let idx = key_index()?;
            cfg.set_ex_data(idx, key);
        }

        Ok(cfg.into_ssl(host)?)
    }

    /// If `host` is an IPv6 address, we must strip away the square brackets that surround
    /// it (otherwise, boring will fail to parse the host as an IP address, eventually
    /// causing the handshake to fail due a hostname verification error).
    fn normalize_host(host: &str) -> &str {
        let normalized = crate::util::strip_ipv6_brackets(host);
        if normalized.len() != host.len() && normalized.parse::<std::net::Ipv6Addr>().is_ok() {
            return normalized;
        }

        host
    }
}

// ====== impl TlsConnectorBuilder =====

impl TlsConnectorBuilder {
    /// Sets the alpn protocol to be used.
    #[inline]
    pub fn alpn_protocol(mut self, protocol: Option<AlpnProtocol>) -> Self {
        self.alpn_protocol = protocol;
        self
    }

    /// Sets the TLS keylog policy.
    #[inline]
    pub fn keylog(mut self, keylog: Option<KeyLog>) -> Self {
        self.keylog = keylog;
        self
    }

    /// Sets the identity to be used for client certificate authentication.
    #[inline]
    pub fn identity(mut self, identity: Option<Identity>) -> Self {
        self.identity = identity;
        self
    }

    /// Sets the certificate store used for TLS verification.
    #[inline]
    pub fn cert_store<T>(mut self, cert_store: T) -> Self
    where
        T: Into<Option<CertStore>>,
    {
        self.cert_store = cert_store.into();
        self
    }

    /// Sets the certificate verification flag.
    #[inline]
    pub fn cert_verification(mut self, enabled: bool) -> Self {
        self.cert_verification = enabled;
        self
    }

    /// Sets the minimum TLS version to use.
    #[inline]
    pub fn min_version<T>(mut self, version: T) -> Self
    where
        T: Into<Option<TlsVersion>>,
    {
        self.min_version = version.into();
        self
    }

    /// Sets the maximum TLS version to use.
    #[inline]
    pub fn max_version<T>(mut self, version: T) -> Self
    where
        T: Into<Option<TlsVersion>>,
    {
        self.max_version = version.into();
        self
    }

    /// Sets the Server Name Indication (SNI) flag.
    #[inline]
    pub fn tls_sni(mut self, enabled: bool) -> Self {
        self.tls_sni = enabled;
        self
    }

    /// Sets the hostname verification flag.
    #[inline]
    pub fn verify_hostname(mut self, enabled: bool) -> Self {
        self.verify_hostname = enabled;
        self
    }

    /// Sets a custom TLS session store.
    #[inline]
    pub fn session_store(mut self, store: Option<Arc<dyn TlsSessionCache>>) -> Self {
        if let Some(store) = store {
            self.session_cache = store;
        }
        self
    }

    /// Build the `TlsConnector` with the provided configuration.
    pub fn build<'a, T>(&self, opts: T) -> crate::Result<TlsConnector>
    where
        T: Into<Cow<'a, TlsOptions>>,
    {
        let opts = opts.into();

        // Replace the default configuration with the provided one
        let max_tls_version = opts.max_tls_version.or(self.max_version);
        let min_tls_version = opts.min_tls_version.or(self.min_version);
        let alpn_protocols = self
            .alpn_protocol
            .map(|proto| Cow::Owned(vec![proto]))
            .or_else(|| opts.alpn_protocols.clone());

        // Create the SslConnector with the provided options
        let mut connector = SslConnector::bare_builder(SslMethod::tls())
            .map_err(Error::tls)?
            .set_identity(self.identity.as_ref())?
            .set_cert_store(self.cert_store.as_ref())?
            .set_cert_verification(self.cert_verification)
            .set_cert_compressors(opts.certificate_compressors.as_deref())?;

        // Set minimum TLS version
        set_option_inner_try!(min_tls_version, connector, set_min_proto_version);

        // Set maximum TLS version
        set_option_inner_try!(max_tls_version, connector, set_max_proto_version);

        // Set OCSP stapling
        set_bool!(opts, enable_ocsp_stapling, connector, enable_ocsp_stapling);

        // Set Signed Certificate Timestamps (SCT)
        set_bool!(
            opts,
            enable_signed_cert_timestamps,
            connector,
            enable_signed_cert_timestamps
        );

        // Set TLS Session ticket options
        set_bool!(
            opts,
            !session_ticket,
            connector,
            set_options,
            SslOptions::NO_TICKET
        );

        // Set TLS PSK DHE key exchange options
        set_bool!(
            opts,
            !psk_dhe_ke,
            connector,
            set_options,
            SslOptions::NO_PSK_DHE_KE
        );

        // Set TLS No Renegotiation options
        set_bool!(
            opts,
            !renegotiation,
            connector,
            set_options,
            SslOptions::NO_RENEGOTIATION
        );

        // Set TLS grease options
        set_option!(opts, grease_enabled, connector, set_grease_enabled);

        // Set TLS permute extensions options
        set_option!(opts, permute_extensions, connector, set_permute_extensions);

        // Set TLS curves list
        set_option_ref_try!(opts, curves_list, connector, set_curves_list);

        // Set TLS signature algorithms list
        set_option_ref_try!(opts, sigalgs_list, connector, set_sigalgs_list);

        // Set TLS prreserve TLS 1.3 cipher list order
        set_option!(
            opts,
            preserve_tls13_cipher_list,
            connector,
            set_preserve_tls13_cipher_list
        );

        // Set TLS cipher list
        set_option_ref_try!(opts, cipher_list, connector, set_cipher_list);

        // Set TLS delegated credentials
        set_option_ref_try!(
            opts,
            delegated_credentials,
            connector,
            set_delegated_credentials
        );

        // Set TLS record size limit
        set_option!(opts, record_size_limit, connector, set_record_size_limit);

        // Set TLS aes hardware override
        set_option!(opts, aes_hw_override, connector, set_aes_hw_override);

        // Set TLS extension permutation
        if let Some(ref extension_permutation) = opts.extension_permutation {
            connector
                .set_extension_permutation(extension_permutation)
                .map_err(Error::tls)?;
        }

        // Set TLS keylog handler.
        if let Some(ref policy) = self.keylog {
            let handle = policy.clone().handle().map_err(Error::tls)?;
            connector.set_keylog_callback(move |_, line| {
                handle.write(line);
            });
        }

        // Create the handshake settings with the default session cache capacity.
        let settings = HandshakeSettings {
            tls_sni: self.tls_sni,
            verify_hostname: self.verify_hostname,
            no_ticket: opts.psk_skip_session_ticket,
            alpn_protocols,
            alps_protocols: opts.alps_protocols.clone(),
            alps_use_new_codepoint: opts.alps_use_new_codepoint,
            enable_ech_grease: opts.enable_ech_grease,
            key_shares: opts.key_shares.clone(),
            random_aes_hw_override: opts.random_aes_hw_override,
        };

        // If the session cache is disabled, we don't need to set up any callbacks.
        let cache = opts.pre_shared_key.then(|| {
            let session_cache = self.session_cache.clone();

            connector.set_session_cache_mode(SslSessionCacheMode::CLIENT);
            connector.set_new_session_callback({
                let cache = session_cache.clone();
                move |ssl, session| {
                    if let Ok(Some(key)) = key_index().map(|idx| ssl.ex_data(idx)) {
                        cache.put(key.clone(), TlsSession(session));
                    }
                }
            });

            session_cache
        });

        // Capture evidence without replacing BoringSSL certificate verification.
        #[allow(unsafe_code)]
        unsafe {
            ffi::SSL_CTX_set_msg_callback(connector.as_ptr(), Some(server_hello_msg_callback));
        }

        Ok(TlsConnector {
            ssl: connector.build(),
            cache,
            settings,
        })
    }
}

/// A stream which may be wrapped with TLS.
pub enum MaybeHttpsStream<T> {
    /// A raw HTTP stream.
    Http(T),
    /// An SSL-wrapped HTTP stream.
    Https(SslStream<T>),
}

/// A connection that has been established with a TLS handshake.
pub struct EstablishedConn<IO> {
    io: IO,
    descriptor: ConnectionDescriptor,
}

// ===== impl MaybeHttpsStream =====

impl<T> AsRef<T> for MaybeHttpsStream<T> {
    #[inline]
    fn as_ref(&self) -> &T {
        match self {
            MaybeHttpsStream::Http(s) => s,
            MaybeHttpsStream::Https(s) => s.get_ref(),
        }
    }
}

impl<T> Connection for MaybeHttpsStream<T>
where
    T: Connection,
{
    #[inline]
    fn connected(&self) -> Connected {
        match self {
            MaybeHttpsStream::Http(s) => s.connected(),
            MaybeHttpsStream::Https(s) => s.get_ref().connected(),
        }
    }
}

impl<T> fmt::Debug for MaybeHttpsStream<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            MaybeHttpsStream::Http(..) => f.pad("Http(..)"),
            MaybeHttpsStream::Https(..) => f.pad("Https(..)"),
        }
    }
}

impl<T> AsyncRead for MaybeHttpsStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    #[inline]
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.as_mut().get_mut() {
            MaybeHttpsStream::Http(inner) => Pin::new(inner).poll_read(cx, buf),
            MaybeHttpsStream::Https(inner) => Pin::new(inner).poll_read(cx, buf),
        }
    }
}

impl<T> AsyncWrite for MaybeHttpsStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    #[inline]
    fn poll_write(
        mut self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.as_mut().get_mut() {
            MaybeHttpsStream::Http(inner) => Pin::new(inner).poll_write(ctx, buf),
            MaybeHttpsStream::Https(inner) => Pin::new(inner).poll_write(ctx, buf),
        }
    }

    #[inline]
    fn poll_flush(mut self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.as_mut().get_mut() {
            MaybeHttpsStream::Http(inner) => Pin::new(inner).poll_flush(ctx),
            MaybeHttpsStream::Https(inner) => Pin::new(inner).poll_flush(ctx),
        }
    }

    #[inline]
    fn poll_shutdown(mut self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.as_mut().get_mut() {
            MaybeHttpsStream::Http(inner) => Pin::new(inner).poll_shutdown(ctx),
            MaybeHttpsStream::Https(inner) => Pin::new(inner).poll_shutdown(ctx),
        }
    }

    #[inline]
    fn is_write_vectored(&self) -> bool {
        match self {
            MaybeHttpsStream::Http(inner) => inner.is_write_vectored(),
            MaybeHttpsStream::Https(inner) => inner.is_write_vectored(),
        }
    }

    #[inline]
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            MaybeHttpsStream::Http(inner) => Pin::new(inner).poll_write_vectored(cx, bufs),
            MaybeHttpsStream::Https(inner) => Pin::new(inner).poll_write_vectored(cx, bufs),
        }
    }
}

// ===== impl EstablishedConn =====

impl<IO> EstablishedConn<IO> {
    /// Creates a new [`EstablishedConn`].
    #[inline]
    pub fn new(io: IO, descriptor: ConnectionDescriptor) -> EstablishedConn<IO> {
        EstablishedConn { io, descriptor }
    }
}
