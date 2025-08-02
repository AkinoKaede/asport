use std::ops::RangeInclusive;

use bitflags::bitflags;
use thiserror::Error;
use uuid::Uuid;

/// Command `ClientHello`
/// ```plain
/// +------+-------+-------+-------+-------+
/// | UUID | TOKEN |  FM   | EPRS  | EPRE  |
/// +------+-------+-------+-------+-------+
/// |  16  |  32   |   1   |   2   |   2   |
/// +------+-------+-------+-------+-------+
/// ```
///
/// where:
///
/// - `UUID` - client UUID
/// - `TOKEN` - client token. The client raw password is hashed into a 256-bit long ¬token using [TLS Keying Material Exporter](https://www.rfc-editor.org/rfc/rfc5705) on current TLS session. While exporting, the `label` should be the client UUID and the `context` should be the raw password.
/// - `FM` - forward mode. The forward mode of the client. It is a bitmask that indicates which protocols the client supports for port forwarding. High 5 bits are reserved for future use and must be set to 0. The low 3 bits are used as follows:
///     - `0b001` - TCP
///     - `0b010` - UDP (native)
///     - `0b100` - UDP (QUIC)
/// - `EPRS` - expected port range start. The start of the port range that the client expects to be forwarded.
/// - `EPRE` - expected port range end. The end of the port range that the client expects to be forwarded. It must be greater than or equal to `EPRS`.
#[derive(Clone, Debug)]
pub struct ClientHello {
    uuid: Uuid,
    token: [u8; 32],
    forward_mode: ForwardMode,
    expected_port_range: RangeInclusive<u16>,
}

impl ClientHello {
    const TYPE_CODE: u8 = 0x00;

    pub const fn new(
        uuid: Uuid,
        token: [u8; 32],
        forward_mode: ForwardMode,
        expected_port_range: RangeInclusive<u16>,
    ) -> Self {
        Self {
            uuid,
            token,
            forward_mode,
            expected_port_range,
        }
    }

    pub fn uuid(&self) -> Uuid {
        self.uuid
    }

    pub fn token(&self) -> [u8; 32] {
        self.token
    }

    pub fn forward_mode(&self) -> ForwardMode {
        self.forward_mode
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

impl From<ClientHello> for (Uuid, [u8; 32], ForwardMode, RangeInclusive<u16>) {
    fn from(hello: ClientHello) -> Self {
        (
            hello.uuid,
            hello.token,
            hello.forward_mode,
            hello.expected_port_range,
        )
    }
}

bitflags! {
    #[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct ForwardMode: u8 {
        const TCP = 1 << 0;
        const UDP_NATIVE = 1 << 1;
        const UDP_QUIC = 1 << 2;

        // Combined modes
        const TCP_UDP_NATIVE = Self::TCP.bits() | Self::UDP_NATIVE.bits();
        const TCP_UDP_QUIC = Self::TCP.bits() | Self::UDP_QUIC.bits();
    }
}

impl ForwardMode {
    pub fn tcp(&self) -> bool {
        self.contains(ForwardMode::TCP)
    }

    pub fn udp(&self) -> bool {
        self.contains(ForwardMode::UDP_NATIVE) || self.contains(ForwardMode::UDP_QUIC)
    }

    pub fn both(&self) -> bool {
        self.contains(ForwardMode::TCP_UDP_NATIVE) || self.contains(ForwardMode::TCP_UDP_QUIC)
    }
}

#[derive(Debug, Error)]
#[error("invalid forward mode: {0}")]
pub struct InvalidForwardMode(u8);

impl TryFrom<u8> for ForwardMode {
    type Error = InvalidForwardMode;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match ForwardMode::from_bits(value) {
            Some(mode) => Ok(mode),
            None => Err(InvalidForwardMode(value)),
        }
    }
}

impl From<ForwardMode> for u8 {
    fn from(mode: ForwardMode) -> Self {
        mode.bits()
    }
}

impl std::fmt::Display for ForwardMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Display the forward mode as a bit sequence (binary)
        write!(f, "{:03b}", self.bits())
    }
}
