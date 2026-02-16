pub mod buffer;
#[cfg(test)]
pub(crate) mod builder;
pub mod crypto;
pub mod customization;
pub mod handshake;
pub mod quic;

#[cfg(test)]
mod diagnostics {
    pub mod handshake_harness;
}

#[derive(PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum Error {
    HandshakeFailed,
    BufferSize,
    UnsupportedVersion,
    Internal,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        core::fmt::Debug::fmt(&self, f)
    }
}

impl core::error::Error for Error {}
