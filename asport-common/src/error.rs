/// Common error variants shared by client and server binaries.
///
/// Invoke as `asport_common_error_variants!(path::ToNetwork, path::ToSecurityType, path::ToModelError);`
/// inside an enum definition that derives `thiserror::Error`.
#[macro_export]
macro_rules! asport_common_error_variants {
    ($network:path, $security:path, $model:path) => {
        #[error(transparent)]
        Io(#[from] std::io::Error),
        #[error(transparent)]
        Rustls(#[from] rustls::Error),
        #[error(transparent)]
        NoInitialCipherSuite(#[from] quinn::crypto::rustls::NoInitialCipherSuite),
        #[error("{0}: {1}")]
        Socket(&'static str, std::io::Error),
        #[error("duplicated authentication")]
        DuplicatedHello,
        #[error("network denied: {0}")]
        NetworkDenied($network),
        #[error("port denied")]
        PortDenied,
        #[error(transparent)]
        Model(#[from] $model),
        #[error("task negotiation timed out")]
        TaskNegotiationTimeout,
        #[error("missing security configuration for {0}")]
        MissingSecurityConfig($security),
        #[error(transparent)]
        QuinnHyphaeCryptoError(#[from] quinn_hyphae::crypto::CryptoError),
    };
}
