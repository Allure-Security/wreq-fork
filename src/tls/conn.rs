//! SSL support via BoringSSL.

#[macro_use]
mod macros;
mod cache;
mod cert_compression;
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

use boring_sys2 as ffi;
use boring2::{
    error::ErrorStack,
    ex_data::Index,
    ssl::{Ssl, SslConnector, SslMethod, SslOptions, SslSessionCacheMode},
};
use cache::{SessionCache, SessionKey};
use http::Uri;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_boring2::SslStream;
use tower::Service;

use crate::{
    Error,
    client::{ConnectIdentity, ConnectRequest, Connected, Connection},
    error::BoxError,
    sync::Mutex,
    tls::{
        AlpnProtocol, AlpsProtocol, CertStore, Identity, KeyLog, TlsOptions, TlsVersion,
        conn::ext::SslConnectorBuilderExt,
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
pub(crate) fn captured_chain_der_index() -> Result<Index<Ssl, Vec<Vec<u8>>>, ErrorStack> {
    static IDX: LazyLock<Result<Index<Ssl, Vec<Vec<u8>>>, ErrorStack>> =
        LazyLock::new(Ssl::new_ex_index);
    IDX.clone()
}

pub(crate) fn captured_chain_der_from_ssl(ssl: &boring2::ssl::SslRef) -> Option<Vec<Vec<u8>>> {
    captured_chain_der_index()
        .ok()
        .and_then(|idx| ssl.ex_data(idx).cloned())
}

/// Raw C callback for SSL_CTX_set_msg_callback.
/// content_type=22 is Handshake. buf starts with handshake type byte:
/// 0x02 = ServerHello.
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
        // boring2::ssl::SslRef is a transparent wrapper around ffi::SSL,
        // so a pointer cast gives us the same &mut SslRef that
        // ForeignTypeRef::from_ptr_mut would, without pulling in
        // foreign_types as a direct dependency.
        let ssl_ref = unsafe { &mut *(ssl as *mut boring2::ssl::SslRef) };
        if let Ok(idx) = server_hello_index() {
            ssl_ref.set_ex_data(idx, hello_body);
        }
    } else if data[0] == 0x08 {
        let ee_body: Vec<u8> = if len > 4 {
            data[4..].to_vec()
        } else {
            data.to_vec()
        };
        let ssl_ref = unsafe { &mut *(ssl as *mut boring2::ssl::SslRef) };
        if let Ok(idx) = encrypted_extensions_index() {
            ssl_ref.set_ex_data(idx, ee_body);
        }
    }
}

type KeyIndexResult = Result<Index<Ssl, SessionKey<ConnectIdentity>>, ErrorStack>;

fn key_index() -> KeyIndexResult {
    static IDX: LazyLock<KeyIndexResult> = LazyLock::new(Ssl::new_ex_index);
    IDX.clone()
}

/// Builds for [`HandshakeConfig`].
pub struct HandshakeConfigBuilder {
    settings: HandshakeConfig,
}

/// Settings for [`TlsConnector`]
#[derive(Clone)]
pub struct HandshakeConfig {
    no_ticket: bool,
    enable_ech_grease: bool,
    verify_hostname: bool,
    tls_sni: bool,
    alpn_protocols: Option<Cow<'static, [AlpnProtocol]>>,
    alps_protocols: Option<Cow<'static, [AlpsProtocol]>>,
    alps_use_new_codepoint: bool,
    random_aes_hw_override: bool,
}

impl HandshakeConfigBuilder {
    /// Skips the session ticket.
    pub fn no_ticket(mut self, skip: bool) -> Self {
        self.settings.no_ticket = skip;
        self
    }

    /// Enables or disables ECH grease.
    pub fn enable_ech_grease(mut self, enable: bool) -> Self {
        self.settings.enable_ech_grease = enable;
        self
    }

    /// Sets hostname verification.
    pub fn verify_hostname(mut self, verify: bool) -> Self {
        self.settings.verify_hostname = verify;
        self
    }

    /// Sets TLS SNI.
    pub fn tls_sni(mut self, sni: bool) -> Self {
        self.settings.tls_sni = sni;
        self
    }

    /// Sets ALPN protocols.
    pub fn alpn_protocols<P>(mut self, alpn_protocols: P) -> Self
    where
        P: Into<Option<Cow<'static, [AlpnProtocol]>>>,
    {
        self.settings.alpn_protocols = alpn_protocols.into();
        self
    }

    /// Sets ALPS protocol.
    pub fn alps_protocols<P>(mut self, alps_protocols: P) -> Self
    where
        P: Into<Option<Cow<'static, [AlpsProtocol]>>>,
    {
        self.settings.alps_protocols = alps_protocols.into();
        self
    }

    /// Sets ALPS new codepoint usage.
    pub fn alps_use_new_codepoint(mut self, use_new: bool) -> Self {
        self.settings.alps_use_new_codepoint = use_new;
        self
    }

    /// Sets random AES hardware override.
    pub fn random_aes_hw_override(mut self, override_: bool) -> Self {
        self.settings.random_aes_hw_override = override_;
        self
    }

    /// Builds the `HandshakeConfig`.
    pub fn build(self) -> HandshakeConfig {
        self.settings
    }
}

impl HandshakeConfig {
    /// Creates a new `HandshakeConfigBuilder`.
    pub fn builder() -> HandshakeConfigBuilder {
        HandshakeConfigBuilder {
            settings: HandshakeConfig::default(),
        }
    }
}

impl Default for HandshakeConfig {
    fn default() -> Self {
        Self {
            no_ticket: false,
            enable_ech_grease: false,
            verify_hostname: true,
            tls_sni: true,
            alpn_protocols: None,
            alps_protocols: None,
            alps_use_new_codepoint: false,
            random_aes_hw_override: false,
        }
    }
}

/// A Connector using BoringSSL to support `http` and `https` schemes.
#[derive(Clone)]
pub struct HttpsConnector<T> {
    http: T,
    inner: Inner,
}

#[derive(Clone)]
struct Inner {
    ssl: SslConnector,
    cache: Option<Arc<Mutex<SessionCache<ConnectIdentity>>>>,
    config: HandshakeConfig,
}

/// A builder for creating a `TlsConnector`.
#[derive(Clone)]
pub struct TlsConnectorBuilder {
    session_cache: Arc<Mutex<SessionCache<ConnectIdentity>>>,
    alpn_protocol: Option<AlpnProtocol>,
    max_version: Option<TlsVersion>,
    min_version: Option<TlsVersion>,
    tls_sni: bool,
    verify_hostname: bool,
    identity: Option<Identity>,
    cert_store: Option<CertStore>,
    cert_verification: bool,
    keylog: Option<KeyLog>,
}

/// A layer which wraps services in an `SslConnector`.
#[derive(Clone)]
pub struct TlsConnector {
    inner: Inner,
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
    pub fn with_connector(http: S, connector: TlsConnector) -> HttpsConnector<S> {
        HttpsConnector {
            http,
            inner: connector.inner,
        }
    }

    /// Disables ALPN negotiation.
    #[inline]
    pub fn no_alpn(&mut self) -> &mut Self {
        self.inner.config.alpn_protocols = None;
        self
    }
}

// ===== impl Inner =====

impl Inner {
    fn setup_ssl(&self, uri: Uri) -> Result<Ssl, BoxError> {
        let cfg = self.ssl.configure()?;
        let host = uri.host().ok_or("URI missing host")?;
        let host = Self::normalize_host(host);
        let ssl = cfg.into_ssl(host)?;
        Ok(ssl)
    }

    fn setup_ssl2(&self, req: ConnectRequest) -> Result<Ssl, BoxError> {
        let mut cfg = self.ssl.configure()?;

        // Use server name indication
        cfg.set_use_server_name_indication(self.config.tls_sni);

        // Verify hostname
        cfg.set_verify_hostname(self.config.verify_hostname);

        // Set ECH grease
        cfg.set_enable_ech_grease(self.config.enable_ech_grease);

        // Set random AES hardware override
        if self.config.random_aes_hw_override {
            let random = (crate::util::fast_random() & 1) == 0;
            cfg.set_aes_hw_override(random);
        }

        // Set ALPS protos
        if let Some(ref alps_values) = self.config.alps_protocols {
            for alps in alps_values.iter() {
                cfg.add_application_settings(alps.0)?;
            }

            // By default, the old endpoint is used.
            if !alps_values.is_empty() && self.config.alps_use_new_codepoint {
                cfg.set_alps_use_new_codepoint(true);
            }
        }

        // Set ALPN protocols
        if let Some(alpn) = req.extra().alpn_protocol() {
            // If ALPN is set in the request, it takes precedence over the connector configuration.
            cfg.set_alpn_protos(&alpn.encode())?;
        } else {
            // Default use the connector configuration.
            if let Some(ref alpn_values) = self.config.alpn_protocols {
                let encoded = AlpnProtocol::encode_sequence(alpn_values.as_ref());
                cfg.set_alpn_protos(&encoded)?;
            }
        }

        let uri = req.uri().clone();
        let host = uri.host().ok_or("URI missing host")?;
        let host = Self::normalize_host(host);

        if let Some(ref cache) = self.cache {
            let key = SessionKey(req.identify());

            // If the session cache is enabled, we try to retrieve the session
            // associated with the key. If it exists, we set it in the SSL configuration.
            if let Some(session) = cache.lock().get(&key) {
                #[allow(unsafe_code)]
                unsafe { cfg.set_session(&session) }?;

                if self.config.no_ticket {
                    cfg.set_options(SslOptions::NO_TICKET)?;
                }
            }

            let idx = key_index()?;
            cfg.set_ex_data(idx, key);
        }

        let ssl = cfg.into_ssl(host)?;
        Ok(ssl)
    }

    /// If `host` is an IPv6 address, we must strip away the square brackets that surround
    /// it (otherwise, boring will fail to parse the host as an IP address, eventually
    /// causing the handshake to fail due a hostname verification error).
    fn normalize_host(host: &str) -> &str {
        if host.is_empty() {
            return host;
        }

        let last = host.len() - 1;
        let mut chars = host.chars();

        if let (Some('['), Some(']')) = (chars.next(), chars.last()) {
            if host[1..last].parse::<std::net::Ipv6Addr>().is_ok() {
                return &host[1..last];
            }
        }

        host
    }
}

// ====== impl TlsConnectorBuilder =====

impl TlsConnectorBuilder {
    /// Sets the alpn protocol to be used.
    #[inline(always)]
    pub fn alpn_protocol(mut self, protocol: Option<AlpnProtocol>) -> Self {
        self.alpn_protocol = protocol;
        self
    }

    /// Sets the TLS keylog policy.
    #[inline(always)]
    pub fn keylog(mut self, keylog: Option<KeyLog>) -> Self {
        self.keylog = keylog;
        self
    }

    /// Sets the identity to be used for client certificate authentication.
    #[inline(always)]
    pub fn identity(mut self, identity: Option<Identity>) -> Self {
        self.identity = identity;
        self
    }

    /// Sets the certificate store used for TLS verification.
    #[inline(always)]
    pub fn cert_store<T>(mut self, cert_store: T) -> Self
    where
        T: Into<Option<CertStore>>,
    {
        self.cert_store = cert_store.into();
        self
    }

    /// Sets the certificate verification flag.
    #[inline(always)]
    pub fn cert_verification(mut self, enabled: bool) -> Self {
        self.cert_verification = enabled;
        self
    }

    /// Sets the minimum TLS version to use.
    #[inline(always)]
    pub fn min_version<T>(mut self, version: T) -> Self
    where
        T: Into<Option<TlsVersion>>,
    {
        self.min_version = version.into();
        self
    }

    /// Sets the maximum TLS version to use.
    #[inline(always)]
    pub fn max_version<T>(mut self, version: T) -> Self
    where
        T: Into<Option<TlsVersion>>,
    {
        self.max_version = version.into();
        self
    }

    /// Sets the Server Name Indication (SNI) flag.
    #[inline(always)]
    pub fn tls_sni(mut self, enabled: bool) -> Self {
        self.tls_sni = enabled;
        self
    }

    /// Sets the hostname verification flag.
    #[inline(always)]
    pub fn verify_hostname(mut self, enabled: bool) -> Self {
        self.verify_hostname = enabled;
        self
    }

    /// Build the `TlsConnector` with the provided configuration.
    pub fn build(&self, opts: &TlsOptions) -> crate::Result<TlsConnector> {
        // Replace the default configuration with the provided one
        let max_tls_version = opts.max_tls_version.or(self.max_version);
        let min_tls_version = opts.min_tls_version.or(self.min_version);
        let alpn_protocols = self
            .alpn_protocol
            .map(|proto| Cow::Owned(vec![proto]))
            .or_else(|| opts.alpn_protocols.clone());

        // Create the SslConnector with the provided options
        let mut connector = SslConnector::no_default_verify_builder(SslMethod::tls_client())
            .map_err(Error::tls)?
            .set_cert_store(self.cert_store.as_ref())?
            .set_cert_verification(self.cert_verification)?
            .add_certificate_compression_algorithms(
                opts.certificate_compression_algorithms.as_deref(),
            )?;

        // Set Identity
        if let Some(ref identity) = self.identity {
            identity.add_to_tls(&mut connector)?;
        }

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

        // Set TLS key shares limit
        set_option!(opts, key_shares_limit, connector, set_key_shares_limit);

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

        // Create the handshake config with the default session cache capacity.
        let config = HandshakeConfig::builder()
            .no_ticket(opts.psk_skip_session_ticket)
            .alpn_protocols(alpn_protocols)
            .alps_protocols(opts.alps_protocols.clone())
            .alps_use_new_codepoint(opts.alps_use_new_codepoint)
            .enable_ech_grease(opts.enable_ech_grease)
            .tls_sni(self.tls_sni)
            .verify_hostname(self.verify_hostname)
            .random_aes_hw_override(opts.random_aes_hw_override)
            .build();

        // If the session cache is disabled, we don't need to set up any callbacks.
        let cache = opts.pre_shared_key.then(|| {
            let cache = self.session_cache.clone();

            connector.set_session_cache_mode(SslSessionCacheMode::CLIENT);
            connector.set_new_session_callback({
                let cache = cache.clone();
                move |ssl, session| {
                    if let Ok(Some(key)) = key_index().map(|idx| ssl.ex_data(idx)) {
                        cache.lock().insert(key.clone(), session);
                    }
                }
            });

            cache
        });

        // Set msg_callback to capture ServerHello bytes for JA4s fingerprinting.
        #[allow(unsafe_code)]
        unsafe {
            ffi::SSL_CTX_set_msg_callback(connector.as_ptr(), Some(server_hello_msg_callback));
        }

        // Capture certificate chain DER during TLS verification.
        //
        // BoringSSL exposes two verify callback APIs:
        //  - set_verify_callback: OpenSSL-compatible, called once per cert in the
        //    chain via the X509_STORE_CTX path. Requires a pre-populated trust
        //    store to even enter the verification state machine; with
        //    `no_default_verify_builder` + SSL_VERIFY_NONE set upstream by
        //    set_cert_verification(false), the state machine is skipped on the
        //    fast path for some TLS 1.2/1.3 flows, so the callback never fires
        //    and no chain lands in ex_data.
        //  - set_custom_verify_callback: BoringSSL-native, called once after
        //    the server Certificate message is received, gets &mut SslRef
        //    directly, and runs regardless of whether a trust store is
        //    configured. This is what we want.
        //
        // With cert_verification=false we always return Ok(()) (accept any
        // cert); the caller validates post-handshake against the scan hostname.
        // With cert_verification=true we still accept any cert (the default
        // boring verify-path is no longer active because we installed this
        // callback) but we still write the chain — downstream validators that
        // care about trusted-CA state run against the captured chain directly.
        let bypass_verify = !self.cert_verification;
        let _ = bypass_verify; // always accept for now; post-handshake validator decides
        connector.set_custom_verify_callback(
            boring2::ssl::SslVerifyMode::PEER,
            move |ssl: &mut boring2::ssl::SslRef| {
                if let Some(chain) = ssl.peer_cert_chain() {
                    let der_chain: Vec<Vec<u8>> =
                        chain.iter().filter_map(|cert| cert.to_der().ok()).collect();
                    if !der_chain.is_empty() {
                        if let Ok(chain_idx) = captured_chain_der_index() {
                            ssl.set_ex_data(chain_idx, der_chain);
                        }
                    }
                }
                Ok(())
            },
        );

        Ok(TlsConnector {
            inner: Inner {
                ssl: connector.build(),
                cache,
                config,
            },
        })
    }
}

// ===== impl TlsConnector =====

impl TlsConnector {
    /// Creates a new `TlsConnectorBuilder` with the given configuration.
    pub fn builder() -> TlsConnectorBuilder {
        const DEFAULT_SESSION_CACHE_CAPACITY: usize = 8;
        TlsConnectorBuilder {
            session_cache: Arc::new(Mutex::new(SessionCache::with_capacity(
                DEFAULT_SESSION_CACHE_CAPACITY,
            ))),
            alpn_protocol: None,
            min_version: None,
            max_version: None,
            identity: None,
            cert_store: None,
            cert_verification: true,
            tls_sni: true,
            verify_hostname: true,
            keylog: None,
        }
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
    req: ConnectRequest,
}

// ===== impl MaybeHttpsStream =====

impl<T> MaybeHttpsStream<T> {
    /// Returns a reference to the underlying stream.
    #[inline]
    pub fn get_ref(&self) -> &T {
        match self {
            MaybeHttpsStream::Http(s) => s,
            MaybeHttpsStream::Https(s) => s.get_ref(),
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

impl<T> Connection for MaybeHttpsStream<T>
where
    T: Connection,
{
    fn connected(&self) -> Connected {
        match self {
            MaybeHttpsStream::Http(s) => s.connected(),
            MaybeHttpsStream::Https(s) => {
                let mut connected = s.get_ref().connected();

                if s.ssl().selected_alpn_protocol() == Some(b"h2") {
                    connected = connected.negotiated_h2();
                }

                connected
            }
        }
    }
}

impl<T> AsyncRead for MaybeHttpsStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
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

    fn poll_flush(mut self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.as_mut().get_mut() {
            MaybeHttpsStream::Http(inner) => Pin::new(inner).poll_flush(ctx),
            MaybeHttpsStream::Https(inner) => Pin::new(inner).poll_flush(ctx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.as_mut().get_mut() {
            MaybeHttpsStream::Http(inner) => Pin::new(inner).poll_shutdown(ctx),
            MaybeHttpsStream::Https(inner) => Pin::new(inner).poll_shutdown(ctx),
        }
    }
}

// ===== impl EstablishedConn =====

impl<IO> EstablishedConn<IO> {
    /// Creates a new [`EstablishedConn`].
    #[inline]
    pub fn new(io: IO, req: ConnectRequest) -> EstablishedConn<IO> {
        EstablishedConn { io, req }
    }
}
