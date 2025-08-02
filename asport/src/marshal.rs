use std::{
    io::{Error as IoError, Write},
    net::SocketAddr,
};

use bytes::{BufMut, BytesMut};
use futures_util::{AsyncWrite, AsyncWriteExt};

use crate::{Address, ClientHello, Connect, Dissociate, Header, Heartbeat, Packet, ServerHello, VERSION};

impl Header {
    /// Marshals the header into an `AsyncWrite` stream
    #[cfg(feature = "async_marshal")]
    pub async fn async_marshal(&self, s: &mut (impl AsyncWrite + Unpin)) -> Result<(), IoError> {
        let mut buf = BytesMut::with_capacity(self.len());
        self.write(&mut buf);
        s.write_all(&buf).await
    }

    /// Marshals the header into a `Write` stream
    #[cfg(feature = "marshal")]
    pub fn marshal(&self, s: &mut impl Write) -> Result<(), IoError> {
        let mut buf = BytesMut::with_capacity(self.len());
        self.write(&mut buf);
        s.write_all(&buf)
    }

    /// Writes the header into a `BufMut`
    pub fn write(&self, buf: &mut impl BufMut) {
        buf.put_u8(VERSION);
        buf.put_u8(self.type_code());

        match self {
            Self::ClientHello(client_hello) => client_hello.write(buf),
            Self::ServerHello(server_hello) => server_hello.write(buf),
            Self::Connect(connect) => connect.write(buf),
            Self::Packet(packet) => packet.write(buf),
            Self::Dissociate(dissociate) => dissociate.write(buf),
            Self::Heartbeat(heartbeat) => heartbeat.write(buf),
        }
    }
}

impl Address {
    fn write(&self, buf: &mut impl BufMut) {
        buf.put_u8(self.type_code());

        match self {
            Self::None => {}
            Self::SocketAddress(SocketAddr::V4(addr)) => {
                buf.put_slice(&addr.ip().octets());
                buf.put_u16(addr.port());
            }
            Self::SocketAddress(SocketAddr::V6(addr)) => {
                for seg in addr.ip().segments() {
                    buf.put_u16(seg);
                }
                buf.put_u16(addr.port());
            }
        }
    }
}

impl ClientHello {
    fn write(&self, buf: &mut impl BufMut) {
        buf.put_slice(self.uuid().as_ref());
        buf.put_slice(&self.token());
        buf.put_u8(self.forward_mode().into());
        buf.put_u16(*self.expected_port_range().start());
        buf.put_u16(*self.expected_port_range().end());
    }
}

impl ServerHello {
    fn write(&self, buf: &mut impl BufMut) {
        buf.put_u8(self.handshake_code());
        if let Some(port) = self.port() {
            buf.put_u16(port);
        }
    }
}

impl Connect {
    fn write(&self, buf: &mut impl BufMut) {
        self.addr().write(buf);
    }
}

impl Packet {
    fn write(&self, buf: &mut impl BufMut) {
        buf.put_u16(self.assoc_id());
        buf.put_u16(self.pkt_id());
        buf.put_u8(self.frag_total());
        buf.put_u8(self.frag_id());
        buf.put_u16(self.size());
        self.addr().write(buf);
    }
}

impl Dissociate {
    fn write(&self, buf: &mut impl BufMut) {
        buf.put_u16(self.assoc_id());
    }
}

impl Heartbeat {
    fn write(&self, _buf: &mut impl BufMut) {}
}
