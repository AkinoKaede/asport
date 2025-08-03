use std::{
    io::{Error as IoError, ErrorKind},
    net::SocketAddr,
};

use bytes::Bytes;
use tokio::{
    io::{self, AsyncWriteExt},
    net::TcpStream,
};
use tokio_util::compat::FuturesAsyncReadCompatExt;

use asport::{Address, ServerHello};
use asport_quinn::{ClientHello, Connect, Packet};

use crate::error::Error;
use crate::utils::UdpForwardMode;

use super::{Connection, ERROR_CODE};

impl Connection {
    pub async fn server_hello(&self, server_hello: ServerHello) {
        match self.model.server_hello(server_hello).await {
            Ok(()) => log::info!(
                "[{id:#010x}] [{addr}] [{user}] [server_hello]",
                id = self.id(),
                addr = self.inner.remote_address(),
                user = self.auth,
            ),
            Err(err) => log::warn!(
                "[{id:#010x}] [{addr}] [{user}] [server_hello] sending server hello error: {err}",
                id = self.id(),
                addr = self.inner.remote_address(),
                user = self.auth,
            ),
        }
    }

    pub async fn connect(&self, addr: SocketAddr) -> Result<Connect, Error> {
        let addr_display = addr.to_string();

        // IPv4-mapped IPv6 convert to IPv4
        /*
        let addr = match addr {
            original_addr @ SocketAddr::V4(_) => original_addr,
            original_addr @ SocketAddr::V6(v6_addr) => {
                match v6_addr.ip().to_ipv4_mapped() {
                    Some(ipv4) => SocketAddr::V4(SocketAddrV4::new(ipv4, original_addr.port())),
                    None => original_addr,
                }
            },
        };
        */

        match self.model.connect(Address::SocketAddress(addr)).await {
            Ok(conn) => Ok(conn),
            Err(err) => {
                log::warn!("[connect] failed initializing forwarding from {addr_display}: {err}");
                Err(Error::Model(err))
            }
        }
    }

    pub async fn handle_packet(&self, pkt: Packet) {
        let assoc_id = pkt.assoc_id();
        let pkt_id = pkt.pkt_id();
        let frag_id = pkt.frag_id();
        let frag_total = pkt.frag_total();

        let mode = self.udp_forward_mode.load().unwrap();

        log::info!(
            "[{id:#010x}] [{addr}] [{user}] [packet] [{assoc_id:#06x}] [from-{mode}] [{pkt_id:#06x}] fragment {frag_id}/{frag_total}",
            id = self.id(),
            addr = self.inner.remote_address(),
            user = self.auth,
            frag_id = frag_id + 1,
        );

        let (pkt, addr, assoc_id) = match pkt.accept().await {
            Ok(None) => return,
            Ok(Some(res)) => res,
            Err(err) => {
                log::warn!(
                    "[{id:#010x}] [{addr}] [{user}] [packet] [{assoc_id:#06x}] [from-{mode}] [{pkt_id:#06x}] fragment {frag_id}/{frag_total}: {err}",
                    id = self.id(),
                    addr = self.inner.remote_address(),
                    user = self.auth,
                    frag_id = frag_id + 1,
                );
                return;
            }
        };

        let process = async {
            log::info!(
                "[{id:#010x}] [{addr}] [{user}] [packet] [{assoc_id:#06x}] [from-{mode}] [{pkt_id:#06x}] to {dst_addr}",
                id = self.id(),
                addr = self.inner.remote_address(),
                user = self.auth,
                dst_addr = addr,
            );

            let sessions = match self.udp_sessions.lock().await.clone() {
                Some(sessions) => sessions,
                None => {
                    return Err(Error::from(IoError::new(
                        ErrorKind::NotFound,
                        "no UDP sessions",
                    )));
                }
            };

            let socket_addr = match addr {
                Address::None => {
                    return Err(Error::from(IoError::new(ErrorKind::NotFound, "no address")));
                }
                Address::SocketAddress(addr) => addr,
            };

            // Validate destination address
            // Because client can send packet with any address, we need to validate it.
            // If not, it can be used for proxy.
            if !self
                .udp_sessions
                .lock()
                .await
                .clone()
                .unwrap()
                .validate(assoc_id, socket_addr)
            {
                // unwrap() is safe because of it's checked.
                return Err(Error::from(IoError::new(
                    ErrorKind::InvalidInput,
                    "destination address is not valid",
                )));
            }

            sessions.send_to(pkt, socket_addr).await
        };

        if let Err(err) = process.await {
            log::warn!(
                "[{id:#010x}] [{addr}] [{user}] [packet] [{assoc_id:#06x}] [from-{mode}] [{pkt_id:#06x}] to {dst_addr}: {err}",
                id = self.id(),
                addr = self.inner.remote_address(),
                user = self.auth,
                dst_addr = addr,
            );
        }
    }

    pub async fn dissociate(&self, assoc_id: u16) -> Result<(), Error> {
        log::info!(
            "[{id:#010x}] [{addr}] [{auth}] [dissociate] [{assoc_id:#06x}]",
            id = self.id(),
            addr = self.inner.remote_address(),
            auth = self.auth,
        );
        match self.model.dissociate(assoc_id).await {
            Ok(()) => Ok(()),
            Err(err) => {
                log::warn!(
                    "[{id:#010x}] [{addr}] [{auth}] [dissociate] [{assoc_id:#06x}] {err}",
                    id = self.id(),
                    addr = self.inner.remote_address(),
                    auth = self.auth,
                );
                Err(Error::Model(err))
            }
        }
    }

    pub async fn handle_client_hello(&self, client_hello: ClientHello) {
        log::info!(
            "[{id:#010x}] [{addr}] [{auth}] [client_hello] {auth_uuid}",
            id = self.id(),
            addr = self.inner.remote_address(),
            auth = self.auth,
            auth_uuid = client_hello.uuid(),
        );
    }

    pub async fn handle_heartbeat(&self) {
        log::info!(
            "[{id:#010x}] [{addr}] [{user}] [heartbeat]",
            id = self.id(),
            addr = self.inner.remote_address(),
            user = self.auth,
        );
    }

    pub async fn forward_tcp(self, (mut stream, addr): (TcpStream, SocketAddr)) {
        match self.connect(addr).await {
            Ok(conn) => {
                log::info!(
                    "[{id:#010x}] [{addr}] [{user}] [connect]",
                    id = self.id(),
                    addr = addr,
                    user = self.auth,
                );

                let mut conn = conn.compat();
                match io::copy_bidirectional(&mut conn, &mut stream).await {
                    Ok(_) => {}
                    Err(err) => {
                        let _ = stream.shutdown().await;
                        let _ = conn.get_mut().reset(ERROR_CODE);
                        log::warn!(
                            "[{id:#010x}] [{addr}] [{user}] [connect] TCP stream forwarding error: {err}",
                            id = self.id(),
                            addr = addr,
                            user = self.auth,
                            err = err,
                        );
                    }
                }
            }

            Err(err) => {
                log::warn!(
                    "[{id:#010x}] [{addr}] [{user}] [connect] unable to forward: {err}",
                    id = self.id(),
                    addr = addr,
                    user = self.auth,
                    err = err,
                );
                return;
            }
        };
    }

    pub async fn forward_packet(
        self,
        pkt: Bytes,
        addr: Address,
        assoc_id: u16,
        dissociate_before_forward: bool,
    ) {
        if dissociate_before_forward {
            let _ = self.dissociate(assoc_id).await;
        }

        let addr_display = addr.to_string();

        let udp_forward_mode = self.udp_forward_mode.load().unwrap();

        log::info!(
            "[{id:#010x}] [{addr}] [{user}] [packet] [{assoc_id:#06x}] [to-{udp_forward_mode}] to {src_addr}",
            id = self.id(),
            addr = self.inner.remote_address(),
            user = self.auth,
            src_addr = addr_display,
        );

        let res = match udp_forward_mode {
            UdpForwardMode::Native => self.model.packet_native(pkt, addr, assoc_id),
            UdpForwardMode::Quic => self.model.packet_quic(pkt, addr, assoc_id).await,
        };

        if let Err(err) = res {
            log::warn!(
                "[{id:#010x}] [{addr}] [{user}] [packet] [{assoc_id:#06x}] [to-{udp_forward_mode}] to {src_addr}: {err}",
                id = self.id(),
                addr = self.inner.remote_address(),
                user = self.auth,
                src_addr = addr_display,
            );
        }
    }
}
