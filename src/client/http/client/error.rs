use std::{error::Error as StdError, fmt};

use bytes::Bytes;
use http::Request;

use super::pool;
#[cfg(feature = "socks")]
use crate::client::conn::socks;
use crate::{
    client::{
        conn::{Connected, tunnel},
        core::{self},
    },
    error::{BoxError, ProxyConnect},
    tls::TlsInfo,
};

#[derive(Debug)]
pub struct Error {
    pub(super) kind: ErrorKind,
    pub(super) source: Option<BoxError>,
    pub(super) connect_info: Option<Connected>,
    pub(super) captured_chain_der: Option<Vec<Bytes>>,
}

#[derive(Debug)]
pub(super) enum ErrorKind {
    Canceled,
    ChannelClosed,
    Connect,
    ProxyConnect,
    UserUnsupportedRequestMethod,
    UserUnsupportedVersion,
    UserAbsoluteUriRequired,
    SendRequest,
}

pub(super) enum ClientConnectError {
    Normal(Error),
    CheckoutIsClosed(pool::Error),
}

#[allow(clippy::large_enum_variant)]
pub(super) enum TrySendError<B> {
    Retryable {
        error: Error,
        req: Request<B>,
        connection_reused: bool,
    },
    Nope(Error),
}

// ==== impl Error ====

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "client error ({:?})", self.kind)
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.source.as_ref().map(|e| &**e as _)
    }
}

impl Error {
    pub(super) fn new<E>(kind: ErrorKind, error: E) -> Self
    where
        E: Into<BoxError>,
    {
        let error = error.into();

        let kind = if error.is::<tunnel::TunnelError>() || error.is::<ProxyConnect>() || {
            #[cfg(feature = "socks")]
            {
                error.is::<socks::SocksError>()
            }
            #[cfg(not(feature = "socks"))]
            {
                false
            }
        } {
            ErrorKind::ProxyConnect
        } else {
            kind
        };

        let captured_chain_der = crate::tls::captured_chain_der_from_error(&*error);

        Self {
            kind,
            source: Some(error),
            connect_info: None,
            captured_chain_der,
        }
    }

    #[inline]
    pub(super) fn new_kind(kind: ErrorKind) -> Self {
        Self {
            kind,
            source: None,
            connect_info: None,
            captured_chain_der: None,
        }
    }

    /// Returns true if this was an error from [`ErrorKind::Connect`].
    #[inline]
    pub fn is_connect(&self) -> bool {
        matches!(self.kind, ErrorKind::Connect)
    }

    /// Returns true if this was an error from [`ErrorKind::ProxyConnect`].
    #[inline]
    pub fn is_proxy_connect(&self) -> bool {
        matches!(self.kind, ErrorKind::ProxyConnect)
    }

    /// Returns the info of the client connection on which this error occurred.
    #[inline]
    pub fn connect_info(&self) -> Option<&Connected> {
        self.connect_info.as_ref()
    }

    #[inline]
    pub(crate) fn captured_chain_der(&self) -> Option<&Vec<Bytes>> {
        self.captured_chain_der.as_ref()
    }

    #[inline]
    pub(super) fn with_connect_info(mut self, connect_info: Connected) -> Self {
        if self.captured_chain_der.is_none() {
            self.captured_chain_der = connect_info
                .extra_ref::<TlsInfo>()
                .and_then(TlsInfo::captured_chain_der_bytes)
                .cloned();
        }
        Self {
            connect_info: Some(connect_info),
            ..self
        }
    }

    #[inline]
    pub(super) fn is_canceled(&self) -> bool {
        matches!(self.kind, ErrorKind::Canceled)
    }

    #[inline]
    pub(super) fn tx(src: core::Error) -> Self {
        Self::new(ErrorKind::SendRequest, src)
    }

    #[inline]
    pub(super) fn closed(src: core::Error) -> Self {
        Self::new(ErrorKind::ChannelClosed, src)
    }
}
