use std::{
    fmt::{Display, Formatter, Result as FmtResult},
    mem,
    net::SocketAddr,
};

#[allow(unused_imports)]
pub use self::{
    client_hello::{ClientHello, ForwardMode, InvalidForwardMode},
    connect::Connect,
    dissociate::Dissociate,
    heartbeat::Heartbeat,
    packet::Packet,
    server_hello::ServerHello,
};

mod client_hello;
mod heartbeat;
mod server_hello;
mod connect;
mod packet;
mod dissociate;

pub const VERSION: u8 = 0x00;

#[non_exhaustive]
#[derive(Clone, Debug)]
pub enum Header {
    ClientHello(ClientHello),
    ServerHello(ServerHello),
    Connect(Connect),
    Packet(Packet),
    Dissociate(Dissociate),
    Heartbeat(Heartbeat),
}

impl Header {
    pub const TYPE_CODE_CLIENT_HELLO: u8 = ClientHello::type_code();
    pub const TYPE_CODE_SERVER_HELLO: u8 = ServerHello::type_code();
    pub const TYPE_CODE_CONNECT: u8 = Connect::type_code();
    pub const TYPE_CODE_PACKET: u8 = Packet::type_code();
    pub const TYPE_CODE_DISSOCIATE: u8 = Dissociate::type_code();
    pub const TYPE_CODE_HEARTBEAT: u8 = Heartbeat::type_code();

    /// Returns the command type code
    pub const fn type_code(&self) -> u8 {
        match self {
            Self::ClientHello(_) => Self::TYPE_CODE_CLIENT_HELLO,
            Self::ServerHello(_) => Self::TYPE_CODE_SERVER_HELLO,
            Self::Connect(_) => Self::TYPE_CODE_CONNECT,
            Self::Packet(_) => Self::TYPE_CODE_PACKET,
            Self::Dissociate(_) => Self::TYPE_CODE_DISSOCIATE,
            Self::Heartbeat(_) => Self::TYPE_CODE_HEARTBEAT,
        }
    }

    /// Returns the serialized length of the command
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        2 + match self {
            Self::ClientHello(client_hello) => client_hello.len(),
            Self::ServerHello(server_hello) => server_hello.len(),
            Self::Connect(connect) => connect.len(),
            Self::Packet(packet) => packet.len(),
            Self::Dissociate(dissociate) => dissociate.len(),
            Self::Heartbeat(heartbeat) => heartbeat.len(),
        }
    }
}


/// Socks5-like variable-length field that encodes the network address
/// Domain is not supported because it not possible that the remote address is a domain.
///
/// ```plain
/// +------+----------+----------+
/// | ATYP |   ADDR   |   PORT   |
/// +------+----------+----------+
/// |  1   | Variable |    2     |
/// +------+----------+----------+
/// ```
///
/// where:
///
/// - `ATYP` - the address type
/// - `ADDR` - the address
/// - `PORT` - the port
///
/// The address type can be one of the following:
///
/// - `0xff`: None
/// - `0x01`: IPv4 address
/// - `0x04`: IPv6 address
///
/// Address type `None` is used in `Packet` commands that is not the first fragment of a UDP packet.
///
/// The port number is encoded in 2 bytes after the Domain name / IP address.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Address {
    None,
    SocketAddress(SocketAddr),
}

impl Address {
    pub const TYPE_CODE_NONE: u8 = 0xff;
    pub const TYPE_CODE_IPV4: u8 = 0x01;
    pub const TYPE_CODE_IPV6: u8 = 0x04;

    /// Returns the address type code
    pub const fn type_code(&self) -> u8 {
        match self {
            Self::None => Self::TYPE_CODE_NONE,
            Self::SocketAddress(addr) => match addr {
                SocketAddr::V4(_) => Self::TYPE_CODE_IPV4,
                SocketAddr::V6(_) => Self::TYPE_CODE_IPV6,
            },
        }
    }

    /// Returns the serialized length of the address
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        1 + match self {
            Address::None => 0,
            Address::SocketAddress(SocketAddr::V4(_)) => 4 + 2,
            Address::SocketAddress(SocketAddr::V6(_)) => 16 + 2,
        }
    }

    /// Takes the address out, leaving a `None` in its place
    pub fn take(&mut self) -> Self {
        mem::take(self)
    }

    /// Returns `true` if the address is `None`
    pub fn is_none(&self) -> bool {
        matches!(self, Self::None)
    }


    /// Returns `true` if the address is an IPv4 address
    pub fn is_ipv4(&self) -> bool {
        matches!(self, Self::SocketAddress(SocketAddr::V4(_)))
    }

    /// Returns `true` if the address is an IPv6 address
    pub fn is_ipv6(&self) -> bool {
        matches!(self, Self::SocketAddress(SocketAddr::V6(_)))
    }
}

impl Display for Address {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            Self::None => write!(f, "none"),
            Self::SocketAddress(addr) => write!(f, "{addr}"),
        }
    }
}

impl Default for Address {
    fn default() -> Self {
        Self::None
    }
}
