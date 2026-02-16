//! Builder to set up typical Hyphae handshake flows.
//! 
//! See the `HandshakeBuilder` documentation for more info.
//! 

use std::sync::Arc;

use crate::customization::{QuinnHandshakeData, HyphaePeerIdentity};
use crate::{Error, config::HyphaeCryptoConfig};
use crate::customization::{HandshakeConfig, HandshakeDriver, PayloadDriver, HandshakeInfo};
use crate::buffer::Buffer;
use crate::crypto::{CryptoError, SecretKeySetup, SyncCryptoBackend};
use base64ct::Encoding;
use rand_core::OsRng;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Hyphae handshake configuration builder for Quinn.
/// 
/// This builder creates a `HandshakeConfig` that can handle most
/// handshake flows instead of fully implementing `HandshakeConfig` by
/// hand.
pub struct HandshakeBuilder<'a, T>
where
    T: Clone + PayloadDriver + QuinnHandshakeData + Send + Sync + 'static
{
    protocol: &'a str,
    prologue: Option<&'a [u8]>,
    s: Option<&'a [u8]>,
    rs: Option<&'a [u8]>,
    rs_from_server_name: bool,
    payload_driver: T,
}

impl <'a> HandshakeBuilder<'a, EmptyPayloadDriver> {
    /// Create a new `HandshakeBuilder` with the selected Noise `protocol`.
    pub fn new(protocol: &'a str) -> Self {
        Self {
            protocol,
            prologue: None,
            s: None,
            rs: None,
            rs_from_server_name: false,
            payload_driver: EmptyPayloadDriver,
        }
    }
}

impl <'a, T> HandshakeBuilder<'a, T>
where
    T: Clone + PayloadDriver + QuinnHandshakeData + Send + Sync + 'static
{
    /// Set the handshake's private key to `s`.
    /// 
    /// Defaults to unset.
    pub fn with_static_key(mut self, s: &'a [u8]) -> Self {
        self.s = Some(s);
        self
    }

    /// Set the handshake's remote public key to `rs`.
    /// 
    /// Defaults to unset.
    pub fn with_remote_public(mut self, rs: &'a [u8]) -> Self {
        self.rs = Some(rs);
        self
    }

    /// Set the handshake's prologue.
    /// 
    /// Defaults to empty.
    pub fn with_prologue(mut self, prologue: &'a [u8]) -> Self {
        self.prologue = Some(prologue);
        self
    }

    /// Use a custom payload driver for this handshake.
    /// 
    /// The supplied `payload_driver` will be cloned for every incoming
    /// and outgoing connection to customize the handshake's behavior.
    /// 
    /// See the `PayloadDriver` and `QuinnHandshakeData` documentation
    /// and the "payload" example for more info.
    pub fn with_cloned_payload_driver<TT> (self, payload_driver: TT) -> HandshakeBuilder<'a, TT>
    where
        TT: Clone + PayloadDriver + QuinnHandshakeData + Send + Sync + 'static,
    {
        HandshakeBuilder {
            protocol: self.protocol,
            prologue: self.prologue,
            s: self.s,
            rs: self.rs,
            rs_from_server_name: self.rs_from_server_name,
            payload_driver,
        }
    }

    /// Set the remote public key to the `server_name` parameter for
    /// outgoing connections, useful for "*K" handshake patterns.
    /// 
    /// When enabled, the `server_name` must be a Base64 encoded public
    /// key of the correct length for the selected Noise protocol.
    /// If the string cannot be decoded or is the wrong length, the
    /// connection will fail.
    /// 
    /// This cannot be combined with `with_remote_public(...)`.
    pub fn with_server_name_as_remote_public(mut self) -> Self {
        self.rs_from_server_name = true;
        self
    }

    /// Build an `Arc<HyphaeCryptoConfig<...>>` for the configured
    /// handshake and `crypto_backend`.
    /// 
    /// `HyphaeCryptoConfig` implements `quinn::crypto::ServerConfig`
    /// and `quinn::crypto::ClientConfig` so this can be used to create
    /// Quinn endpoints for the configured handshake.
    /// 
    /// You can pass this to one of the endpoint creation methods in the
    /// `helper` module or set up the endpoint manually.
    /// 
    /// See the "basic" example for more details.
    pub fn build<B: SyncCryptoBackend> (self, crypto_backend: B)
        -> Result<Arc<HyphaeCryptoConfig<BasicHandshakeConfig<T>, B>>, CryptoError>
    {
        if !crypto_backend.protocol_supported(&self.protocol) {
            return Err(CryptoError::UnsupportedProtocol);
        }

        Ok(HyphaeCryptoConfig::new_with_backend(self.build_handshake_config()?, crypto_backend))
    }

    fn build_handshake_config(self) -> Result<BasicHandshakeConfig<T>, CryptoError> {
        if self.rs_from_server_name && self.rs.is_some() {
            return Err(CryptoError::InvalidInitialization);
        }

        Ok(BasicHandshakeConfig {
            protocol: self.protocol.into(),
            prologue: self.prologue.map(Vec::from),
            s: self.s.map(Vec::from),
            rs: self.rs.map(Vec::from),
            rs_from_server_name: self.rs_from_server_name,
            payload_driver: self.payload_driver
        })
    }
}

/// Handshake configuration for handshakes created by the `HandshakeBuilder`.
/// 
/// `BasicHandshakeConfig` sets up the Noise handshake parameters from
/// the builder. No preamble is sent and non-empty preambles are rejected.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct BasicHandshakeConfig<T: PayloadDriver + Clone> {
    protocol: String,
    prologue: Option<Vec<u8>>,
    s: Option<Vec<u8>>,
    rs: Option<Vec<u8>>,
    rs_from_server_name: bool,
    #[zeroize(skip)]
    payload_driver: T,
}

impl <T> HandshakeConfig for BasicHandshakeConfig<T>
where
    T: Clone + PayloadDriver + QuinnHandshakeData + Send + Sync + 'static
{
    type Driver = BasicHandshakeDriver<T>;

    fn new_initiator(&self, server_name: &str, noise_handshake: &mut impl HandshakeInfo) -> Result<Self::Driver, Error> {
        let sn_rs = if self.rs_from_server_name {
            let Ok(sn_rs) =  base64ct::Base64::decode_vec(server_name) else {
                return Err(Error::Internal);
            };
            Some(sn_rs)
        } else {
            None
        };

        noise_handshake.initialize(
            &mut OsRng,
            &self.protocol, 
            self.prologue.as_ref().map(Vec::as_slice).unwrap_or(b""),
            self.s.as_ref().map(Vec::as_slice).map(SecretKeySetup::from),
            sn_rs.as_ref().or(self.rs.as_ref()).map(Vec::as_slice))?;
        
        Ok(BasicHandshakeDriver{
            payload_driver: self.payload_driver.clone()
        })
    }

    fn new_responder(&self, preamble: &[u8], noise_handshake: &mut impl HandshakeInfo) -> Result<Self::Driver, Error> {
        if !preamble.is_empty() {
            return Err(Error::HandshakeFailed);
        }

        noise_handshake.initialize(
            &mut OsRng,
            &self.protocol, 
            self.prologue.as_ref().map(Vec::as_slice).unwrap_or(b""),
            self.s.as_ref().map(Vec::as_slice).map(SecretKeySetup::from),
            self.rs.as_ref().map(Vec::as_slice))?;
        
        Ok(BasicHandshakeDriver{
            payload_driver: self.payload_driver.clone()
        })
    }
}

/// Handshake driver for handshakes created by the `HandshakeBuilder`.
/// 
/// `BasicHandshakeDriver` is a pass-through to builder's payload driver
/// and defaults all other handshake behavior.
pub struct BasicHandshakeDriver<T: PayloadDriver + Clone> {
    payload_driver: T,
}

impl <T: PayloadDriver + QuinnHandshakeData + Clone> HandshakeDriver for BasicHandshakeDriver<T> {}

impl <T: PayloadDriver + QuinnHandshakeData + Clone> PayloadDriver for BasicHandshakeDriver<T> {

    fn write_noise_payload(&mut self, payload_buffer: &mut impl Buffer, noise_handshake: &mut impl HandshakeInfo) -> Result<(), Error> {
        self.payload_driver.write_noise_payload(payload_buffer, noise_handshake)
    }

    fn read_noise_payload(&mut self, payload: &[u8], noise_handshake: &mut impl HandshakeInfo) -> Result<(), Error> {
        self.payload_driver.read_noise_payload(payload, noise_handshake)
    }
}

impl <T: PayloadDriver + QuinnHandshakeData + Clone> QuinnHandshakeData for BasicHandshakeDriver<T> {
    type HandshakeData = T::HandshakeData;

    type PeerIdentity = T::PeerIdentity;

    fn handshake_data(&self) -> Option<Self::HandshakeData> {
        self.payload_driver.handshake_data()
    }

    fn peer_identity(&self, remote_public: Option<&[u8]>, final_handshake_hash: Option<&[u8]>) -> Option<Self::PeerIdentity> {
        self.payload_driver.peer_identity(remote_public, final_handshake_hash)
    }
}

/// Empty payload driver for handshakes created by the `HandshakeBuilder`.
/// 
/// This payload driver sends empty payloads and fails the handshake if
/// it receives a non-empty payload.
/// 
/// It returns empty `()` for calls to `handshake_data` and uses the
/// default `HyphaePeerIdentity` for calls to `peer_identity`.
#[derive(Clone)]
pub struct EmptyPayloadDriver;

impl PayloadDriver for EmptyPayloadDriver {
    fn write_noise_payload(&mut self, _payload_buffer: &mut impl Buffer, _noise_handshake: &mut impl HandshakeInfo) -> Result<(), Error> {
        Ok(())
    }

    fn read_noise_payload(&mut self, payload: &[u8], _noise_handshake: &mut impl HandshakeInfo) -> Result<(), Error> {
        match payload.is_empty() {
            true => Ok(()),
            false => Err(Error::HandshakeFailed),
        }
    }
}

impl QuinnHandshakeData for EmptyPayloadDriver {
    type HandshakeData = ();

    type PeerIdentity = HyphaePeerIdentity;

    fn handshake_data(&self) -> Option<Self::HandshakeData> {
        Some(())
    }

    fn peer_identity(&self, remote_public: Option<&[u8]>, final_handshake_hash: Option<&[u8]>) -> Option<Self::PeerIdentity> {
        Some(HyphaePeerIdentity::new(remote_public, final_handshake_hash))
    }
}
