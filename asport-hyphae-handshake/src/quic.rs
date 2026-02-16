use crate::Error;

/// QUIC version number for QUIC version 1 (RFC 9000) connections
/// secured with the Hyphae version 1 handshake.
/// 
/// In big-endian, it is the bytes `b"HQ\x01\x01"`. E.g.
/// "hyphae-h-v1.quic-v1.", the 3rd byte representing the handshake
/// version and the 4th byte representing the QUIC version.
pub const HYPHAE_H_V1_QUIC_V1_VERSION: u32 = 0x48510101;

/// Hyphae transport label for QUIC version 1.
pub const QUIC_V1_TRANSPORT_LABEL: &'static [u8] = b"quic-v1";

/// Map a handshake `Error` to a TLS error code that can be used to
/// close a QUIC connection with a failed handshake.
pub fn to_tls_error_code(err: Error) -> u8{
    const TLS_HANDSHAKE_FAILED: u8 = 40;
    const TLS_INTERNAL_ERROR: u8 = 80;

    match err {
        Error::HandshakeFailed |
        Error::UnsupportedVersion => TLS_HANDSHAKE_FAILED,
        _ => TLS_INTERNAL_ERROR
    }
}
