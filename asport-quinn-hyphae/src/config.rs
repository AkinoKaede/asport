//! Implementation of `quinn::crypto::ClientConfig` and `ServerConfig`
//! for Hyphae `HandshakeConfig`.
//! 

use std::sync::Arc;

use hyphae_handshake::{crypto::{InitialCrypto, SymmetricKey, SyncCryptoBackend, TransportCrypto, HYPHAE_AEAD_TAG_LEN}, customization::SyncHandshakeConfig, handshake::HandshakeVersion, quic::{HYPHAE_H_V1_QUIC_V1_VERSION, QUIC_V1_TRANSPORT_LABEL}};
use quinn_proto::{crypto, transport_parameters::TransportParameters, ConnectError, ConnectionId};

use crate::{session::HyphaeSession, sessionkeys::initial_keys, util::HandshakeMessageFramer, customization::QuinnHandshakeData};

/// Hyphae `HandshakeConfig` wrapper for Quinn crypto configuration.
/// 
/// `HyphaeCryptoConfig` wraps a Hyphae `HandshakeConfig` and 
/// `CryptoBackend`, implementing `quinn::crypto::ClientConfig` and
/// `quinn::crypto::ServerConfig` to set up Quinn endpoints and
/// connections.
/// 
/// `HandshakeBuilder::build()` creates this type for you. You only need
/// to use this directly if you implement your own `HandshakeConfig`.
pub struct HyphaeCryptoConfig<T, B>
where
    T: SyncHandshakeConfig,
    T::Driver: QuinnHandshakeData,
    B: SyncCryptoBackend,
{
    pub(crate) handshake_config: T,
    pub(crate) crypto: Arc<B>,
}

impl <T, B> HyphaeCryptoConfig<T, B>
where
    T: SyncHandshakeConfig,
    T::Driver: QuinnHandshakeData,
    B: SyncCryptoBackend,
{
    /// Create a new `HandshakeConfig` wrapper for use with Quinn.
    /// 
    /// Both `handshake_config` and `crypto_backend` must be able to be
    /// shared across threads. Additionally, the handshake driver for
    /// the configuration must implement `QuinnHandshakeData`.
    pub fn new_with_backend(handshake_config: T, crypto_backend: B) -> Arc<Self> {
        Arc::new(Self {
            handshake_config,
            crypto: Arc::new(crypto_backend),
        })
    }

    /// Get a reference to the configuration's `CryptoBackend`.
    pub fn crypto_backend(&self) -> &B {
        &self.crypto
    }
}

impl <T, B> crypto::ClientConfig for HyphaeCryptoConfig<T, B>
where
    T: SyncHandshakeConfig,
    T::Driver: QuinnHandshakeData,
    B: SyncCryptoBackend,
{
    fn start_session(
        self: Arc<Self>,
        version: u32,
        server_name: &str,
        params: &TransportParameters,
    ) -> Result<Box<dyn crypto::Session>, ConnectError> {
        let mut transport_params = Vec::new();
        params.write(&mut transport_params);

        if version != HYPHAE_H_V1_QUIC_V1_VERSION {
            return Err(ConnectError::UnsupportedVersion);
        }

        let session = HyphaeSession {
            config: self.clone(),
            handshake_data_ready: false,
            failed: false,
            initiator: true,
            handshake: None,
            rekey: None,
            framer: HandshakeMessageFramer::default(),
            params: Some(transport_params),
            peer_params: None,
            server_name: Some(server_name.into()),
        };
        Ok(Box::new(session))
    }
}

impl <T, B> crypto::ServerConfig for HyphaeCryptoConfig<T, B>
where
    T: SyncHandshakeConfig,
    T::Driver: QuinnHandshakeData,
    B: SyncCryptoBackend,
{
    fn initial_keys(
        &self,
        version: u32,
        dst_cid: &quinn_proto::ConnectionId,
    ) -> Result<crypto::Keys, crypto::UnsupportedVersion> {
        if version != HYPHAE_H_V1_QUIC_V1_VERSION {
            return Err(crypto::UnsupportedVersion);
        }

        Ok(initial_keys(false, HandshakeVersion::Version1, QUIC_V1_TRANSPORT_LABEL, &dst_cid, &self.crypto.initial_crypto()))
    }

    fn retry_tag(&self, version: u32, orig_dst_cid: &ConnectionId, packet: &[u8]) -> [u8; HYPHAE_AEAD_TAG_LEN] {
        if version != HYPHAE_H_V1_QUIC_V1_VERSION {
            // Quinn cannot have initial keys for an unknown version.
            unreachable!();
        }

        let initial_crypto = self.crypto.initial_crypto();
        let mut retry_key = SymmetricKey::default();
        initial_crypto.retry_tag_secret(HandshakeVersion::Version1, QUIC_V1_TRANSPORT_LABEL, &orig_dst_cid, &mut retry_key)
            .expect("initial crypto can generate retry secret");

        let mut packet_in_place = Vec::with_capacity(packet.len() + HYPHAE_AEAD_TAG_LEN);
        packet_in_place.extend_from_slice(packet);
        packet_in_place.extend_from_slice(&[0u8; HYPHAE_AEAD_TAG_LEN]);
        initial_crypto.encrypt_in_place(&retry_key, 0, b"", &mut packet_in_place)
            .expect("initial crypto can encrypt retry packet");

        packet_in_place[packet.len()..].try_into().unwrap()
    }

    fn start_session(
        self: Arc<Self>,
        version: u32,
        params: &quinn_proto::transport_parameters::TransportParameters,
    ) -> Box<dyn crypto::Session> {
        if version != HYPHAE_H_V1_QUIC_V1_VERSION {
            // Quinn cannot have initial keys for an unknown version.
            unreachable!();
        }

        let mut transport_params = Vec::new();
        params.write(&mut transport_params);

        let session = HyphaeSession {
            config: self.clone(),
            handshake_data_ready: false,
            failed: false,
            initiator: false,
            handshake: None,
            rekey: None,
            framer: HandshakeMessageFramer::default(),
            params: Some(transport_params),
            peer_params: None,
            server_name: None,
        };
        Box::new(session)
    }
}
