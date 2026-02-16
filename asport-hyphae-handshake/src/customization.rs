use rand_core::{CryptoRng, RngCore};

use crate::{buffer::Buffer, crypto::{CryptoError, SecretKeySetup}, Error};

pub trait HandshakeConfig {
    type Driver: HandshakeDriver;

    fn new_initiator(&self, server_name: &str, handshake: &mut impl HandshakeInfo) -> Result<Self::Driver, Error>;

    fn new_responder(&self, preamble: &[u8], handshake: &mut impl HandshakeInfo) -> Result<Self::Driver, Error>;

    #[allow(unused_variables)]
    fn initiator_preamble(&self, preamble_buffer: &mut impl Buffer) -> Result<(), Error> {
        Ok(())
    }
}

pub trait HandshakeDriver: PayloadDriver {
    #[allow(unused_variables)]
    fn write_final_payload(&mut self, payload_buffer: &mut impl Buffer, handshake: &mut impl HandshakeInfo) -> Result<(), Error>{
        Ok(())
    }

    #[allow(unused_variables)]
    fn read_final_payload(&mut self, payload: &[u8], handshake: &mut impl HandshakeInfo) -> Result<(), Error>{
        Ok(())
    }
}

pub trait PayloadDriver {
    fn write_noise_payload(&mut self, payload_buffer: &mut impl Buffer, handshake: &mut impl HandshakeInfo) -> Result<(), Error>;

    fn read_noise_payload(&mut self, payload: &[u8], handshake: &mut impl HandshakeInfo) -> Result<(), Error>;
}

/// Handshake info and control trait for use by handshake and payload
/// drivers.
pub trait HandshakeInfo {
    /// Initialize the handshake's Noise protocol.
    /// 
    /// This can only be called by the driver's `new_initiator` and
    /// `new_responder` methods.
    fn initialize(&mut self, rng: &mut (impl CryptoRng + RngCore), protocol: &str, prologue: &[u8], s: Option<SecretKeySetup>, rs: Option<&[u8]>) -> Result<(), CryptoError>;

    /// Set a handshake token (such as a PSK).
    /// 
    /// This can be called at any time before final payloads.
    /// 
    /// This is passed through to the crypto backend's Noise handshake
    /// implementation.
    fn set_token(&mut self, token: &str, value: &[u8]) -> Result<(), CryptoError>;

    /// Returns `true` if the peer is the handshake initiator.
    fn is_initiator(&self) -> bool;

    /// Returns `true` if the Noise handshake if finished.
    /// 
    /// This will always be false until the last payload read and for
    /// final message.
    fn is_finished(&self) -> bool;

    /// Returns the current message position (indexed from 1).
    /// 
    /// When called from `write_noise_message` this will be the position
    /// of the message the payload is going into. When called from
    /// `read_noise_message` this will be the position of the message
    /// the payload is from. Returns `None` during initialization and
    /// final message processing.
    /// 
    /// As an example, a "Noise_XX" handshake will have three message
    /// positions: 1, 2, and 3.
    fn handshake_position(&self) -> Option<u8>;

    /// Returns the remote public key if it is available.
    fn remote_public(&self) -> Option<&[u8]>;

    /// Returns the handshake hash as of the last *fully processed*
    /// Noise message.
    /// 
    /// **Warning!** When called from `read_noise_payload`, this is the
    /// hash as of the previous message, not the one that contained the
    /// payload that was just passed to `read_noise_payload`. This
    /// allows message hash signatures created in `write_noise_payload`
    /// to be validated in the peer's `read_noise_payload`.
    fn prev_handshake_hash(&self) -> Option<&[u8]>;

    /// Returns the final hash of the Noise handshake if the handshake
    /// is finished.
    fn final_handshake_hash(&self) -> Option<&[u8]>;
}

/// Trait for `HandshakeConfig`s that can be shared between threads.
/// 
/// This has a blanket implementation for any `HandshakeConfig` with
/// a `HandshakeDriver` that is also `Send + Sync + 'static`.
pub trait SyncHandshakeConfig:
    HandshakeConfig<Driver: Send + Sync + 'static> +
    Send + Sync + 'static
{}

impl <T> SyncHandshakeConfig for T
where
    T: HandshakeConfig + Send + Sync + 'static,
    T::Driver: Send + Sync + 'static,
{}
