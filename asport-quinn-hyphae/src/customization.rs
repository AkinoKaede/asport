//! Traits for full customization of Hyphae's handshake flow.
//! 
//! For typical handshake flows, use the `HandshakeBuilder`.
//! 

// Re-export Hyphae handshake customization traits.
pub use hyphae_handshake::customization::*;

/// Quinn `handshake_data` and `peer_identity` mapping for handshake
/// drivers.
/// 
/// This can be used to customize the early handshake data and peer
/// identity returned by Quinn's `handshake_data()` and `peer_identity()`
/// calls.
/// 
/// This must be implemented for custom payload drivers passed to the
/// builder and on the handshake driver of a customized handshake
/// configuration. See the implementation of `EmptyPayloadDriver` for
/// a starting point.
pub trait QuinnHandshakeData {
    /// Early handshake data type returned by calls to `handshake_data()`.
    /// 
    /// `EmptyPayloadDriver` sets this to the unit type as it does not
    /// support any early handshake data.
    /// 
    /// Quinn wraps this in a `Box<dyn Any>`.
    type HandshakeData: 'static;

    /// Peer identity data type returned by calls to `peer_identity()`.
    /// 
    /// `EmptyPayloadDriver` sets this to `HyphaePeerIdentity`.
    /// 
    /// Quinn wraps this in a `Box<dyn Any>`.
    type PeerIdentity: 'static;

    /// Supply early handshake data to callers of `handshake_data()`.
    /// 
    /// This may be called multiple times (or never) as it is a direct
    /// pass-through. Once this returns `Some`, it must always return
    /// `Some`. This must return `Some` by the time the Noise handshake
    /// is finished.
    fn handshake_data(&self) -> Option<Self::HandshakeData>;

    /// Supply peer identity to callers of `peer_identity()`.
    /// 
    /// This may be called multiple times (or never) as it is a direct
    /// pass-through. This must return `Some` by the time the Noise
    /// handshake is finished.
    /// 
    /// The remote public key and final Noise handshake hash are
    /// supplied if they are available. You can use these to create a
    /// `HyphaePeerIdentity` or a custom type for your application
    /// specific handshake.
    fn peer_identity(&self, remote_public: Option<&[u8]>, final_handshake_hash: Option<&[u8]>) -> Option<Self::PeerIdentity>;
}

/// Default type for Hyphae peer identities.
#[non_exhaustive]
pub struct HyphaePeerIdentity {
    /// Peer's public key if one is available.
    pub remote_public: Option<Vec<u8>>,

    /// Final hash of the Noise handshake once the handshake is complete.
    pub final_handshake_hash: Option<Vec<u8>>,
}

impl HyphaePeerIdentity {
    /// Create a new `HyphaePeerIdentity` with the supplied remote
    /// public key and final handshake hash.
    pub fn new(remote_public: Option<&[u8]>, final_handshake_hash: Option<&[u8]>) -> Self {
        HyphaePeerIdentity {
            remote_public: remote_public.map(Vec::from),
            final_handshake_hash: final_handshake_hash.map(Vec::from),
        }
    }
}

impl std::fmt::Debug for HyphaePeerIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use base64ct::Encoding as _;
        let rs = self.remote_public.as_ref().map(Vec::as_slice).map(base64ct::Base64::encode_string);
        let h = self.final_handshake_hash.as_ref().map(Vec::as_slice).map(base16ct::upper::encode_string);
        f.debug_struct("HyphaePeerIdentity")
            .field("remote_public", &rs)
            .field("final_handshake_hash", &h)
            .finish()
    }
}
