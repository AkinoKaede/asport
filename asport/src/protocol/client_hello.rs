use std::ops::RangeInclusive;

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
/// - `TOKEN` - client token. The client raw password is hashed into a 256-bit long token using [TLS Keying Material Exporter](https://www.rfc-editor.org/rfc/rfc5705) on current TLS session. While exporting, the `label` should be the client UUID and the `context` should be the raw password.
/// - `FM` - forward mode. The forward mode of the client. It can be: `0x00` for TCP, `0x01` for UDP native, `0x02` for UDP QUIC, `0x03` for TCP + UDP native, `0x04` for TCP + UDP QUIC.
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
        Self { uuid, token, forward_mode, expected_port_range }
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
        (hello.uuid, hello.token, hello.forward_mode, hello.expected_port_range)
    }
}

#[derive(Copy, Clone, Debug)]
#[repr(u8)]
pub enum ForwardMode {
    Tcp = 0x00,
    UdpNative = 0x01, // UDP forward with QUIC unreliable datagram
    UdpQuic = 0x02, // UDP forward with QUIC unidirectional stream
    // Combine
    TcpUdpNative = 0x03, // Tcp + UdpNative
    TcpUdpQuic = 0x04, // Tcp + UdpQuic
}

impl ForwardMode {
    pub fn tcp(&self) -> bool {
        match self {
            ForwardMode::Tcp | ForwardMode::TcpUdpNative | ForwardMode::TcpUdpQuic => true,
            _ => false,
        }
    }

    pub fn udp(&self) -> bool {
        match self {
            ForwardMode::UdpNative | ForwardMode::UdpQuic | ForwardMode::TcpUdpNative | ForwardMode::TcpUdpQuic => true,
            _ => false,
        }
    }

    pub fn both(&self) -> bool {
        match self {
            ForwardMode::TcpUdpNative | ForwardMode::TcpUdpQuic => true,
            _ => false,
        }
    }
}

#[derive(Debug, Error)]
#[error("invalid forward mode: {0}")]
pub struct InvalidForwardMode(u8);

impl TryFrom<u8> for ForwardMode {
    type Error = InvalidForwardMode;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(ForwardMode::Tcp),
            0x01 => Ok(ForwardMode::UdpNative),
            0x02 => Ok(ForwardMode::UdpQuic),
            0x03 => Ok(ForwardMode::TcpUdpNative),
            0x04 => Ok(ForwardMode::TcpUdpQuic),
            _ => Err(InvalidForwardMode(value)),
        }
    }
}

impl From<ForwardMode> for &[u8] {
    fn from(mode: ForwardMode) -> Self {
        match mode {
            ForwardMode::Tcp => &[0x00],
            ForwardMode::UdpNative => &[0x01],
            ForwardMode::UdpQuic => &[0x02],
            ForwardMode::TcpUdpNative => &[0x03],
            ForwardMode::TcpUdpQuic => &[0x04],
        }
    }
}