use std::ops::RangeInclusive;

use bitflags::bitflags;
use thiserror::Error;
use uuid::Uuid;

/// Command `ClientHello`
/// ```plain
/// +------+-------+-------+-------+-------+
/// | UUID | TOKEN | FLAGS | EPRS  | EPRE  |
/// +------+-------+-------+-------+-------+
/// |  16  |  32   |   1   |   2   |   2   |
/// +------+-------+-------+-------+-------+
/// ```
///
/// where:
///
/// - `UUID` - client UUID
/// - `TOKEN` - client token. The client raw password is hashed into a 256-bit long ¬token using [TLS Keying Material Exporter](https://www.rfc-editor.org/rfc/rfc5705) on current TLS session. While exporting, the `label` should be the client UUID and the `context` should be the raw password.
/// - `FLAGS` - Flags. It is a bitmask that indicates which protocols the client supports for port forwarding currently. High 5 bits are reserved for future use and must be set to 0. The low 3 bits are used as follows:
///     - `0b001` - TCP
///     - `0b010` - UDP Enabled
///     - `0b100` - UDP Mode QUIC (if UDP is enabled, this flag indicates that the client enables QUIC mode; if not set, it means native UDP mode is enabled).
/// - `EPRS` - expected port range start. The start of the port range that the client expects to be forwarded.
/// - `EPRE` - expected port range end. The end of the port range that the client expects to be forwarded. It must be greater than or equal to `EPRS`.
#[derive(Clone, Debug)]
pub struct ClientHello {
    uuid: Uuid,
    token: [u8; 32],
    flags: Flags,
    expected_port_range: RangeInclusive<u16>,
}

impl ClientHello {
    const TYPE_CODE: u8 = 0x00;

    pub const fn new(
        uuid: Uuid,
        token: [u8; 32],
        flags: Flags,
        expected_port_range: RangeInclusive<u16>,
    ) -> Self {
        Self {
            uuid,
            token,
            flags,
            expected_port_range,
        }
    }

    pub fn uuid(&self) -> Uuid {
        self.uuid
    }

    pub fn token(&self) -> [u8; 32] {
        self.token
    }

    pub fn flags(&self) -> Flags {
        self.flags
    }

    pub fn expected_port_range(&self) -> RangeInclusive<u16> {
        self.expected_port_range.clone()
    }

    pub const fn type_code() -> u8 {
        Self::TYPE_CODE
    }

    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        16 + 32 + 1 + 2 + 2
    }
}

impl From<ClientHello> for (Uuid, [u8; 32], Flags, RangeInclusive<u16>) {
    fn from(hello: ClientHello) -> Self {
        (
            hello.uuid,
            hello.token,
            hello.flags,
            hello.expected_port_range,
        )
    }
}

bitflags! {
    #[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct Flags: u8 {
        const TCP = 1 << 0;
        const UDP_ENABLED = 1 << 1;
        const UDP_MODE_QUIC = 1 << 2; // if UDP is enabled, this flag indicates that the client enables QUIC mode; if not set, it means native UDP mode is enabled
    }
}

#[derive(Debug, Error)]
#[error("invalid flags: {0}")]
pub struct InvalidFlags(u8);

impl TryFrom<u8> for Flags {
    type Error = InvalidFlags;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match Flags::from_bits(value) {
            Some(flags) => Ok(flags),
            None => Err(InvalidFlags(value)),
        }
    }
}

impl From<Flags> for u8 {
    fn from(mode: Flags) -> Self {
        mode.bits()
    }
}

impl std::fmt::Display for Flags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Display the flags as a bit sequence (binary)
        write!(f, "{:03b}", self.bits())
    }
}
