use std::io::Error as IoError;

use quinn::{crypto::rustls::NoInitialCipherSuite, ConnectError, ConnectionError};
use quinn_hyphae::crypto::CryptoError;
use rustls::Error as RustlsError;
use rustls_native_certs::Error as RustlsNativeCertsError;
use thiserror::Error;

use asport_quinn::Error as ModelError;

use crate::utils::{Network, SecurityType};

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] IoError),
    #[error(transparent)]
    Connect(#[from] ConnectError),
    #[error("load native certificates error: {0:?}")]
    LoadNativeCerts(Vec<RustlsNativeCertsError>),
    #[error(transparent)]
    Rustls(#[from] RustlsError),
    #[error(transparent)]
    NoInitialCipherSuite(#[from] NoInitialCipherSuite),
    #[error("{0}: {1}")]
    Socket(&'static str, IoError),
    #[error("timeout establishing connection")]
    Timeout,
    #[error("duplicated authentication")]
    DuplicatedHello,
    #[error("authentication failed")]
    AuthFailed,
    #[error("remote bind failed")]
    RemoteBindFailed,
    #[error("network denied: {0}")]
    NetworkDenied(Network),
    #[error("port denied")]
    PortDenied,
    #[error(transparent)]
    Model(#[from] ModelError),
    #[error("cannot resolve the server name")]
    DnsResolve,
    #[error("task negotiation timed out")]
    TaskNegotiationTimeout,
    #[error("invalid packet source")]
    WrongPacketSource,
    #[error("missing address")]
    MissingAddress,
    #[error("missing security configuration for {0}")]
    MissingSecurityConfig(SecurityType),
    #[error(transparent)]
    QuinnHyphaeCryptoError(#[from] CryptoError),
}

impl From<ConnectionError> for Error {
    fn from(err: ConnectionError) -> Self {
        Self::Io(IoError::from(err))
    }
}
