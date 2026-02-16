//! Hyphae Handshake *(Noise Handshakes for QUIC)*
//! ==============================================
//!
//! Hyphae secures QUIC with Noise instead of TLS.
//!
//! Unlike other Noise handshake proposals for QUIC, Hyphae supports *all
//! Noise handshake patterns* (not just IK). Hyphae supports custom Noise
//! payloads.
//! 
//! ### Features:
//! 
//! - Secure QUIC connections with a Noise handshake instead of TLS
//! - Use **any handshake pattern**, AEAD, and hash algorithm (not just IK)
//! - Quinn support in the `quinn-hyphae` crate
//! - Customizable:
//!   - Applications have complete control of the Noise handshake
//!   - Pluggable cryptographic and Noise backends (with built-in support
//!     for Rust Crypto)
//! - Optional key-logging for diagnostics
//! - QUIC header protection and initial packet space obfuscation
//! 
//! ### Examples
//! 
//! See the [README](https://github.com/WillBuik/hyphae-handshake)
//! for more info and examples.
//! 

pub mod builder;
pub mod config;
pub mod customization;
#[cfg(any(test, feature = "helper"))]
pub mod helper;
mod session;
mod sessionkeys;
pub mod tokenkeys;
mod util;

// Re-export Hyphae buffer traits.
pub use hyphae_handshake::buffer;

/// Re-exported types from `hyphae_handshake::crypto`.
pub mod crypto {
    pub use hyphae_handshake::crypto::CryptoError;
    pub use hyphae_handshake::crypto::CryptoBackend;
    pub use hyphae_handshake::crypto::SyncCryptoBackend;
    pub use hyphae_handshake::crypto::SecretKeySetup;

    // Re-export Hyphae keylog.
    #[cfg(feature = "keylog")]
    pub use hyphae_handshake::crypto::keylog;
}

// Re-export Hyphae crypto backends.
pub use hyphae_handshake::crypto::backends::rustcrypto::RustCryptoBackend;

// Re-export constants from `hyphae_handshake::quic`.
pub use hyphae_handshake::quic::HYPHAE_H_V1_QUIC_V1_VERSION;

// Re-export Error.
pub use hyphae_handshake::Error;

// Re-export common `quinn_hyphae` types.
pub use builder::HandshakeBuilder;
pub use customization::HyphaePeerIdentity;

#[cfg(test)]
mod tests;
