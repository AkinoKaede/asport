use std::io::Error as IoError;

use quinn::{ConnectionError, crypto::rustls::NoInitialCipherSuite};
use rustls::Error as RustlsError;
use thiserror::Error;
use uuid::Uuid;
use asport::Flags;
use asport_quinn::Error as ModelError;
use crate::utils::Network;

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] IoError),
    #[error(transparent)]
    Rustls(#[from] RustlsError),
    #[error(transparent)]
    NoInitialCipherSuite(#[from] NoInitialCipherSuite),
    #[error("invalid max idle time")]
    InvalidMaxIdleTime,
    #[error("connection timed out")]
    TimedOut,
    #[error("connection locally closed")]
    LocallyClosed,
    #[error(transparent)]
    Model(#[from] ModelError),
    #[error("duplicated authentication")]
    DuplicatedHello,
    #[error("authentication failed: {0}")]
    AuthFailed(Uuid),
    #[error("bind failed")]
    BindFailed,
    #[error("network denied: {0}")]
    NetworkDenied(Network),
    #[error("port denied")]
    PortDenied,
    #[error("{0}: {1}")]
    Socket(&'static str, IoError),
    #[error("task negotiation timed out")]
    TaskNegotiationTimeout,
    #[error("invalid private key: {0}")]
    InvalidPrivateKey(&'static str),
    #[error("invalid flags: {0}")]
    InvalidFlags(Flags),
}

impl Error {
    pub fn is_trivial(&self) -> bool {
        matches!(self, Self::TimedOut | Self::LocallyClosed)
    }
}

impl From<ConnectionError> for Error {
    fn from(err: ConnectionError) -> Self {
        match err {
            ConnectionError::TimedOut => Self::TimedOut,
            ConnectionError::LocallyClosed => Self::LocallyClosed,
            _ => Self::Io(IoError::from(err)),
        }
    }
}
