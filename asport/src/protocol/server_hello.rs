/// Command `ServerHello`
/// ```plain
/// +------+------+
/// | CODE | PORT |
/// +------+------+
/// |  1   |   2  |
/// +------+------+
/// ```
///
/// where:
/// - `CODE` - the result of Handshake
/// - `PORT` - the port that the server listens on for this client
#[derive(Clone, Debug)]
pub enum ServerHello {
    Success(u16),
    AuthFailed,
    BindFailed,
    PortDenied,
    NetworkDenied,
}

impl ServerHello {
    pub const TYPE_CODE: u8 = 0x01;

    pub const HANDSHAKE_CODE_SUCCESS: u8 = 0x00;
    pub const HANDSHAKE_CODE_AUTH_FAILED: u8 = 0x01;
    pub const HANDSHAKE_CODE_BIND_FAILED: u8 = 0x02;
    pub const HANDSHAKE_CODE_PORT_DENIED: u8 = 0x03;
    pub const HANDSHAKE_CODE_NETWORK_DENIED: u8 = 0x04;

    pub const fn type_code() -> u8 {
        Self::TYPE_CODE
    }

    pub fn handshake_code(&self) -> u8 {
        match self {
            Self::Success(_) => Self::HANDSHAKE_CODE_SUCCESS,
            Self::AuthFailed => Self::HANDSHAKE_CODE_AUTH_FAILED,
            Self::BindFailed => Self::HANDSHAKE_CODE_BIND_FAILED,
            Self::PortDenied => Self::HANDSHAKE_CODE_PORT_DENIED,
            Self::NetworkDenied => Self::HANDSHAKE_CODE_NETWORK_DENIED,
        }
    }

    pub fn port(&self) -> Option<u16> {
        match self {
            Self::Success(port) => Some(*port),
            _ => None,
        }
    }

    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        1 + match self {
            Self::Success(_) => 2,
            _ => 0,
        }
    }
}

impl From<ServerHello> for (u8, Option<u16>) {
    fn from(server_hello: ServerHello) -> (u8, Option<u16>) {
        (server_hello.handshake_code(), server_hello.port())
    }
}
