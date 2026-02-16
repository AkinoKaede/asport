//! Traits for Noise handshakes and encryption primitives needed by Hyphae.
//! 

use rand_core::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::handshake::HandshakeVersion;

pub mod backends;
#[cfg(any(test, feature = "keylog"))]
pub mod keylog;
pub mod noise;
pub mod transport;

#[derive(Debug)]
pub enum CryptoError {
    DecryptionFailed,
    InvalidProtocol,
    UnsupportedProtocol,
    UnsupportedSecretKey,
    InvalidInitialization,
    InvalidKeySize,
    InvalidState,
    InsufficientBuffer,
    StateExhausted,
    Internal,
}

impl core::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        core::fmt::Debug::fmt(&self, f)
    }
}

impl core::error::Error for CryptoError {}

pub const HYPHAE_AEAD_KEY_LEN: usize = 32;
pub const HYPHAE_AEAD_TAG_LEN: usize = 16;
pub const HYPHAE_AEAD_NONCE_LEN: usize = 12;
pub const HYPHAE_HEADER_SAMPLE_LEN: usize = 16;
pub const HYPHAE_HEADER_MASK_MAX_LEN: usize = 16;

#[derive(Clone, Zeroize, ZeroizeOnDrop, Default)]
pub struct SymmetricKey ([u8; Self::SIZE]);

impl SymmetricKey {
    pub const SIZE: usize = HYPHAE_AEAD_KEY_LEN;
}

impl AsRef<[u8; Self::SIZE]> for SymmetricKey {
    fn as_ref(&self) -> &[u8; Self::SIZE] {
        &self.0
    }
}

impl AsMut<[u8; Self::SIZE]> for SymmetricKey {
    fn as_mut(&mut self) -> &mut [u8; Self::SIZE] {
        &mut self.0
    }
}

#[non_exhaustive]
pub enum SecretKeySetup<'a> {
    /// Use a local, long-term secret key `s` that will be copied into
    /// the handshake state.
    Local (&'a [u8]),

    /// Use the backend's configured `RemoteKey` as the long-term
    /// secret key `s`.
    BackendRemote,
}

impl SecretKeySetup<'_> {
    pub fn remote() -> SecretKeySetup<'static> {
        SecretKeySetup::BackendRemote
    }
}

impl <'a> From<&'a [u8]> for SecretKeySetup<'a> {
    fn from(value: &'a [u8]) -> Self {
        SecretKeySetup::Local(value)
    }
}

pub trait CryptoBackend {
    /// Backend's `InitialCrypto` implementation.
    type InitialCrypto: InitialCrypto;

    /// Backend's `NoiseHandshake` implementation.
    type NoiseHandshake: NoiseHandshake;

    /// Backend's `TransportCrypto` implementation.
    type TransportCrypto: TransportCrypto;

    /// Backend's `TransportRekey` implementation.
    type TransportRekey: TransportRekey;

    /// Returns `true` if the backend's `NoiseHandshake` supports
    /// `noise_protocol`.
    fn protocol_supported(&self, noise_protocol: &str) -> bool;

    /// Returns `InitialCrypto`.
    /// 
    /// `InitialCrypto` is used to obfuscate data in the initial
    /// packet space and calculate retry packet integrity tags.
    /// 
    /// Hyphae initial crypto always uses `ChaChaPoly` and `BLAKE2s`.
    fn initial_crypto(&self) -> Self::InitialCrypto;

    /// Returns a new, uninitialized `NoiseHandshake` or an error if the
    /// backend is not properly configured.
    fn new_handshake(&self) -> Result<Self::NoiseHandshake, CryptoError>;

    /// Returns `TransportCrypto` for the handshake's selected AEAD
    /// and hash algorithm.
    /// 
    /// `TransportCrypto` is used to protect data in the handshake,
    /// 0-RTT, and 1-RTT packet spaces.
    fn transport_crypto(&self, handshake: &Self::NoiseHandshake) -> Result<Self::TransportCrypto, CryptoError>;
    
    /// Extract the 1-RTT rekey chain from a finished handshake.
    fn export_1rtt_rekey(&self, handshake: &mut Self::NoiseHandshake, rekey: &mut Self::TransportRekey) -> Result<(), CryptoError>;

}

pub trait NoiseHandshake {
    fn initialize<'a> (
        &mut self,
        rng: &mut (impl CryptoRng + RngCore),
        protocol_name: &str,
        initiator: bool,
        prologue: impl Iterator<Item = &'a[u8]>,
        s: Option<SecretKeySetup>,
        rs: Option<&[u8]>
    ) -> Result<(), CryptoError>;

    fn write_message_in_place(&mut self, buffer: &mut [u8]) -> Result<(), CryptoError>;

    fn read_message_in_place<'a> (&mut self, buffer: &'a mut [u8]) -> Result<&'a [u8], CryptoError>;

    fn next_message_layout(&self) -> Result<(usize, usize), CryptoError>;

    fn is_reset(&self) -> bool;

    fn is_initiator(&self) -> bool;

    fn is_my_turn(&self) -> bool;

    fn is_finished(&self) -> bool;

    fn remote_public(&self) -> Option<&[u8]>;

    fn handshake_hash(&self) -> &[u8];

    fn get_ask(&mut self, label: &[u8], key: &mut SymmetricKey) -> Result<(), CryptoError>;

    /// Export keying material similar to TLS export_keying_material
    /// 
    /// This function derives key material from the handshake state using the
    /// final handshake hash, custom label, and optional context.
    /// 
    /// Parameters:
    /// - label: Application-defined label (similar to TLS exporter label)
    /// - context: Optional context information
    /// - output: Buffer to write the derived key material
    fn export_keying_material(&self, label: &[u8], context: &[u8], output: &mut [u8]) -> Result<(), CryptoError>;
}

pub trait InitialCrypto: TransportCrypto {
    fn initial_level_secret(&self, handshake_version: HandshakeVersion, transport_label: &[u8], client_dcid: &[u8], level_secret: &mut SymmetricKey) -> Result<(), CryptoError>;

    fn retry_tag_secret(&self, handshake_version: HandshakeVersion, transport_label: &[u8], client_dcid: &[u8], level_secret: &mut SymmetricKey) -> Result<(), CryptoError>;
}

pub trait TransportCrypto: Clone {
    type Hash: Send + Sync + 'static;

    fn zeros_hash(&self) -> Self::Hash;

    // todo remove
    fn hash_into(&self, message: &[u8], output: &mut Self::Hash);

    fn hkdf(&self, key: &Self::Hash, ikm: &[u8], info: &[u8], output: &mut Self::Hash);

    fn hash_as_slice<'a> (&self, hash: &'a Self::Hash) -> &'a [u8];

    fn hash_as_mut_slice<'a> (&self, hash: &'a mut Self::Hash) -> &'a  mut[u8];

    fn derive_subkey(&self, level_secret: &SymmetricKey, label: &[u8], output_key: &mut SymmetricKey);

    fn aead_confidentiality_limit(&self) -> u64;

    fn aead_integrity_limit(&self) -> u64;

    fn encrypt_in_place(&self, packet_key: &SymmetricKey, packet_id: u64, ad: &[u8], buffer: &mut [u8]) -> Result<(), CryptoError>;

    fn decrypt_in_place<'a> (&self, packet_key: &SymmetricKey, packet_id: u64, ad: &[u8], buffer: &'a mut [u8]) -> Result<&'a [u8], CryptoError>;

    fn header_protection_mask(&self, header_key: &SymmetricKey, sample: &[u8], mask: &mut [u8]) -> Result<(), CryptoError>;
}

pub trait TransportRekey: Default {
    fn next_1rtt_secret(&mut self, level_secret: &mut SymmetricKey);
}

/// Trait for `CryptoBackend`s that can be shared between threads.
/// 
/// This has a blanket implementation for any `CryptoBackend` with
/// associated types that are also `Send + Sync + 'static`.
pub trait SyncCryptoBackend:
    CryptoBackend<
        InitialCrypto: Send + Sync + 'static,
        NoiseHandshake:  Send + Sync + 'static,
        TransportCrypto: Send + Sync + 'static,
        TransportRekey: Send + Sync + 'static,
    > + Sync + Send + 'static
{}

impl <B> SyncCryptoBackend for B
where
    B: CryptoBackend + Send + Sync + 'static,
    B::InitialCrypto: Send + Sync + 'static,
    B::NoiseHandshake: Send + Sync + 'static,
    B::TransportCrypto: Send + Sync + 'static,
    B::TransportRekey: Send + Sync + 'static,
{}
