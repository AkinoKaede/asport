use std::{
    fmt::{Debug, Formatter, Result as FmtResult},
    ops::RangeInclusive
};

use uuid::Uuid;

use crate::{ClientHello as ClientHelloHeader, ForwardMode, Header};

use super::side::{self, Side};

/// The model of the `ClientHello` command
pub struct ClientHello<M> {
    inner: Side<Tx, Rx>,
    _marker: M,
}

struct Tx {
    header: Header,
}

impl ClientHello<side::Tx> {
    pub(super) fn new(
        uuid: Uuid,
        password: impl AsRef<[u8]>,
        exporter: &impl KeyingMaterialExporter,
        forward_mode: impl Into<ForwardMode>,
        expected_port_range: RangeInclusive<u16>,
    ) -> Self {
        Self {
            inner: Side::Tx(Tx {
                header: Header::ClientHello(ClientHelloHeader::new(
                    uuid,
                    exporter.export_keying_material(uuid.as_ref(), password.as_ref()),
                    forward_mode.into(),
                    expected_port_range,
                )),
            }),
            _marker: side::Tx,
        }
    }

    /// Returns the header of the `ClientHello` command
    pub fn header(&self) -> &Header {
        let Side::Tx(tx) = &self.inner else { unreachable!() };
        &tx.header
    }
}

impl Debug for ClientHello<side::Tx> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        let Side::Tx(tx) = &self.inner else { unreachable!() };
        f.debug_struct("Authenticate")
            .field("header", &tx.header)
            .finish()
    }
}

struct Rx {
    uuid: Uuid,
    token: [u8; 32],
    forward_mode: ForwardMode,
    expected_port_range: RangeInclusive<u16>,
}

impl ClientHello<side::Rx> {
    pub(super) fn new(
        uuid: Uuid,
        token: [u8; 32],
        forward_mode: ForwardMode,
        expected_port_range: RangeInclusive<u16>,
    ) -> Self {
        Self {
            inner: Side::Rx(Rx { uuid, token, forward_mode, expected_port_range }),
            _marker: side::Rx,
        }
    }

    /// Returns the UUID of the peer
    pub fn uuid(&self) -> Uuid {
        let Side::Rx(rx) = &self.inner else { unreachable!() };
        rx.uuid
    }

    /// Returns the token of the peer
    pub fn token(&self) -> [u8; 32] {
        let Side::Rx(rx) = &self.inner else { unreachable!() };
        rx.token
    }

    /// Returns whether the token is valid
    pub fn is_valid(
        &self,
        password: impl AsRef<[u8]>,
        exporter: &impl KeyingMaterialExporter,
    ) -> bool {
        let Side::Rx(rx) = &self.inner else { unreachable!() };
        rx.token == exporter.export_keying_material(rx.uuid.as_ref(), password.as_ref())
    }

    /// Returns the forward mode of the peer
    pub fn forward_mode(&self) -> ForwardMode {
        let Side::Rx(rx) = &self.inner else { unreachable!() };
        rx.forward_mode
    }

    /// Returns the expected port range of the peer
    pub fn expected_port_range(&self) -> RangeInclusive<u16> {
        let Side::Rx(rx) = &self.inner else { unreachable!() };
        rx.expected_port_range.clone()
    }
}

impl Debug for ClientHello<side::Rx> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        let Side::Rx(rx) = &self.inner else { unreachable!() };
        f.debug_struct("Authenticate")
            .field("uuid", &rx.uuid)
            .field("token", &rx.token)
            .field("forward_mode", &rx.forward_mode)
            .field("expected_port_range", &rx.expected_port_range)
            .finish()
    }
}

/// The trait for exporting keying material
pub trait KeyingMaterialExporter {
    /// Exports keying material
    fn export_keying_material(&self, label: &[u8], context: &[u8]) -> [u8; 32];
}
