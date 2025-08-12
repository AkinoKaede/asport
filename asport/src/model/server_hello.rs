use std::fmt::{Debug, Formatter, Result as FmtResult};

use crate::{Header, ServerHello as ServerHelloHeader};

use super::side::{self, Side};

/// The model of the `ServerHello` command
pub struct ServerHello<M> {
    inner: Side<Tx, Rx>,
    _marker: M,
}

struct Tx {
    header: Header,
}

impl ServerHello<side::Tx> {
    pub(super) fn new(server_hello: ServerHelloHeader) -> Self {
        Self {
            inner: Side::Tx(Tx {
                header: Header::ServerHello(server_hello),
            }),
            _marker: side::Tx,
        }
    }

    /// Returns the header of the `ServerHello` command
    pub fn header(&self) -> &Header {
        let Side::Tx(tx) = &self.inner else {
            unreachable!()
        };
        &tx.header
    }
}

struct Rx {
    handshake_code: u8,
    port: Option<u16>,
}

impl ServerHello<side::Rx> {
    pub(super) fn new(handshake_code: u8, port: Option<u16>) -> Self {
        Self {
            inner: Side::Rx(Rx {
                handshake_code,
                port,
            }),
            _marker: side::Rx,
        }
    }

    /// Returns the handshake code of the `ServerHello` command
    pub fn handshake_code(&self) -> u8 {
        let Side::Rx(rx) = &self.inner else {
            unreachable!()
        };
        rx.handshake_code
    }

    /// Returns the port of the `ServerHello` command
    pub fn port(&self) -> Option<u16> {
        let Side::Rx(rx) = &self.inner else {
            unreachable!()
        };
        rx.port
    }
}

impl Debug for ServerHello<side::Rx> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        let Side::Rx(rx) = &self.inner else {
            unreachable!()
        };
        f.debug_struct("ServerHello")
            .field("handshake_code", &rx.handshake_code)
            .field("port", &rx.port)
            .finish()
    }
}
