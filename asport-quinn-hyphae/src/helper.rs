//! Helper functions to create Quinn `Endpoints` with Hyphae's QUIC
//! version number configured.
//! 
//! If your application requires further customization of the endpoint's
//! settings, you can use the code in this module as a starting point.
//! 

use std::io;
use std::net::UdpSocket;
use std::sync::Arc;

use quinn::{Endpoint, EndpointConfig, TransportConfig};

use crate::crypto::SyncCryptoBackend;
use crate::customization::SyncHandshakeConfig;
use crate::tokenkeys::{HyphaeHandshakeTokenKey, HyphaeHmacKey};
use crate::{config::HyphaeCryptoConfig, customization::QuinnHandshakeData, HYPHAE_H_V1_QUIC_V1_VERSION};

/// Create a bidirectional Hyphae endpoint on `socket`.
/// 
/// `crypto_config` is used for both incoming and outgoing (default)
/// connections.
/// 
/// If set, `transport_config` is used for both incoming and outgoing
/// connections.
pub fn hyphae_bidirectional_endpoint<C, B> (
    crypto_config: Arc<HyphaeCryptoConfig<C, B>>,
    transport_config: Option<Arc<TransportConfig>>,
    socket: UdpSocket
) -> io::Result<Endpoint>
where
    C: SyncHandshakeConfig,
    C::Driver: QuinnHandshakeData,
    B: SyncCryptoBackend,
{
    let mut endpoint = hyphae_server_endpoint(crypto_config.clone(), transport_config.clone(), socket)?;
    let mut client_config = hyphae_client_config(crypto_config);
    if let Some(t) = transport_config {
        client_config.transport_config(t);
    }
    endpoint.set_default_client_config(client_config);
    Ok(endpoint)
}

/// Create a Hyphae server endpoint on `socket`.
/// 
/// If set, `transport_config` is used for both incoming connections.
pub fn hyphae_server_endpoint<C, B> (
    server_crypto: Arc<HyphaeCryptoConfig<C, B>>, 
    transport_config: Option<Arc<TransportConfig>>,
    socket: UdpSocket
) -> io::Result<Endpoint>
where
    C: SyncHandshakeConfig,
    C::Driver: QuinnHandshakeData,
    B: SyncCryptoBackend,
{
    let endpoint_config = hyphae_endpoint_config(server_crypto.crypto_backend());
    let mut server_config = hyphae_server_config(server_crypto);
    if let Some(t) = transport_config {
        server_config.transport_config(t);
    }
    Endpoint::new(endpoint_config, Some(server_config), socket, quinn_runtime()?)
}

/// Create a Hyphae client endpoint on `socket`.
/// 
/// `default_client_crypto` is used by default for outgoing connections.
/// 
/// If set, `transport_config` is used for both incoming connections.
pub fn hyphae_client_endpoint<C, B> (
    default_client_crypto: Arc<HyphaeCryptoConfig<C, B>>,
    transport_config: Option<Arc<TransportConfig>>,
    socket: UdpSocket
) -> io::Result<Endpoint>
where
    C: SyncHandshakeConfig,
    C::Driver: QuinnHandshakeData,
    B: SyncCryptoBackend,
{
    let mut endpoint = Endpoint::new(hyphae_endpoint_config(default_client_crypto.crypto_backend()), None, socket, quinn_runtime()?)?;
    let mut client_config = hyphae_client_config(default_client_crypto);
    if let Some(t) = transport_config {
        client_config.transport_config(t);
    }
    endpoint.set_default_client_config(client_config);
    Ok(endpoint)
}

/// Create a `quinn::EndpointConfig` Hyphae's QUIC version number.
pub fn hyphae_endpoint_config<B> (crypto_backend: &B) -> EndpointConfig 
where 
    B: SyncCryptoBackend,
{
    let mut endpoint_config = EndpointConfig::new(Arc::new(HyphaeHmacKey::new(crypto_backend)));
    endpoint_config.supported_versions(vec![HYPHAE_H_V1_QUIC_V1_VERSION]);
    endpoint_config
}

/// Create a `quinn::ClientConfig` Hyphae's QUIC version number for
/// `client_crypto`.
pub fn hyphae_client_config<C, B> (client_crypto: Arc<HyphaeCryptoConfig<C, B>>) -> quinn::ClientConfig
where
    C: SyncHandshakeConfig,
    C::Driver: QuinnHandshakeData,
    B: SyncCryptoBackend,
{
    let mut client_config = quinn::ClientConfig::new(client_crypto);
    client_config.version(HYPHAE_H_V1_QUIC_V1_VERSION);
    client_config
}

/// Create a `quinn::ServerConfig` Hyphae's QUIC version number for
/// `server_crypto`.
pub fn hyphae_server_config<C, B> (server_crypto: Arc<HyphaeCryptoConfig<C, B>>) -> quinn::ServerConfig
where
    C: SyncHandshakeConfig,
    C::Driver: QuinnHandshakeData,
    B: SyncCryptoBackend,
{
    let token_crypto = Arc::new(HyphaeHandshakeTokenKey::new(server_crypto.crypto_backend()));
    quinn::ServerConfig::new(server_crypto, token_crypto)
}

/// Helper to get the Quinn runtime wrapper.
fn quinn_runtime() -> io::Result<Arc<dyn quinn::Runtime>> {
    quinn::default_runtime()
        .ok_or(io::Error::new(
            io::ErrorKind::Other, 
            "no quinn default runtime")
        )
}
