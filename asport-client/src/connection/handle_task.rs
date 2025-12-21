use std::{
    collections::hash_map::Entry,
    io::{Error as IoError, ErrorKind},
    time::Duration,
};

use bytes::Bytes;
use quinn::ZeroRttAccepted;
use tokio::{
    io::{self, AsyncWriteExt},
    net::TcpStream,
    time,
};
use tokio_util::compat::FuturesAsyncReadCompatExt;

use asport::Address;
use asport_quinn::{Connect, Packet, ServerHello};

use crate::{
    error::Error,
    utils::{
        union_proxy_protocol_addresses, ClientHelloFlagsBuilder, ProxyProtocol, UdpForwardMode,
    },
};

use super::{udp_session::UdpSession, Connection, ERROR_CODE};

impl Connection {
    pub async fn client_hello(self, zero_rtt_accepted: Option<ZeroRttAccepted>) {
        if let Some(zero_rtt_accepted) = zero_rtt_accepted {
            log::debug!("[client_hello] waiting for connection to be fully established");
            zero_rtt_accepted.await;
        }

        log::debug!("[client_hello] sending client hello");

        match self
            .model
            .client_hello(
                self.uuid,
                self.password.clone(),
                ClientHelloFlagsBuilder::new(self.network, self.udp_forward_mode),
                self.expected_port_range,
            )
            .await
        {
            Ok(()) => log::info!("[client_hello] {uuid}", uuid = self.uuid),
            Err(err) => log::warn!("[client_hello] client hello sending error: {err}"),
        }
    }

    pub async fn heartbeat(self, heartbeat: Duration) {
        loop {
            time::sleep(heartbeat).await;

            if self.is_closed() {
                break;
            }

            match self.model.heartbeat().await {
                Ok(()) => log::debug!("[heartbeat]"),
                Err(err) => log::warn!("[heartbeat] {err}"),
            }
        }
    }

    pub async fn handle_server_hello(&self, server_hello: ServerHello) {
        log::info!(
            "[server_hello] remote port: {port}",
            port = server_hello.port().unwrap()
        ); // safe to unwrap
    }

    pub async fn handle_connect(&self, conn: Connect) {
        let source_addr_string = conn.addr().to_string();
        log::info!("[connect] {source_addr_string}");

        let source_addr = match conn.addr() {
            Address::SocketAddress(addr) => Some(*addr),
            Address::None => None,
        };

        let process = async {
            let mut stream = None;
            let mut last_err = None;
            let mut local_addr = None;
            match self.local.resolve().await {
                Ok(addrs) => {
                    for addr in addrs {
                        match TcpStream::connect(addr).await {
                            Ok(s) => {
                                stream = Some(s);
                                local_addr = Some(addr);
                                break;
                            }
                            Err(err) => last_err = Some(Error::from(err)),
                        }
                    }
                }
                Err(err) => last_err = Some(err),
            }

            if let Some(mut stream) = stream {
                let addresses = union_proxy_protocol_addresses(source_addr, local_addr.unwrap());

                let proxy_protocol_header = match (self.proxy_protocol, addresses) {
                    (ProxyProtocol::None, _) => None,
                    (ProxyProtocol::V1, Some(addresses)) => {
                        let v1 = ppp::v1::Addresses::from(addresses).to_string();
                        Some(Bytes::from(v1))
                    }
                    (ProxyProtocol::V2, Some(addresses)) => {
                        let v2 = ppp::v2::Builder::with_addresses(
                            ppp::v2::Version::Two | ppp::v2::Command::Proxy,
                            ppp::v2::Protocol::Stream,
                            addresses,
                        )
                        .build()
                        .unwrap();
                        Some(Bytes::from(v2))
                    }
                    _ => {
                        return Err(Error::MissingAddress);
                    }
                };

                if let Some(header) = proxy_protocol_header {
                    let _ = stream.write(&header).await;
                }

                let mut conn = conn.compat();
                let res = io::copy_bidirectional(&mut conn, &mut stream).await;
                let _ = conn.get_mut().reset(ERROR_CODE);
                let _ = stream.shutdown().await;
                res?;
                Ok::<_, Error>(())
            } else {
                let _ = conn.compat().shutdown().await;
                Err(last_err.unwrap_or_else(|| {
                    Error::from(IoError::new(ErrorKind::NotFound, "no address resolved"))
                }))?
            }
        };

        match process.await {
            Ok(()) => {}
            Err(err) => log::warn!("[connect] {source_addr_string}: {err}"),
        }
    }

    pub async fn handle_packet(&self, pkt: Packet) {
        let assoc_id = pkt.assoc_id();
        let pkt_id = pkt.pkt_id();
        let frag_id = pkt.frag_id();
        let frag_total = pkt.frag_total();

        log::info!(
            "[packet] [{assoc_id:#06x}] [from-{mode}] [{pkt_id:#06x}] fragment {frag_id}/{frag_total}",
            mode = self.udp_forward_mode,
            frag_id = frag_id + 1,
        );

        let (pkt, addr, assoc_id) = match pkt.accept().await {
            Ok(None) => return,
            Ok(Some(res)) => res,
            Err(err) => {
                log::warn!(
                    "[packet] [{assoc_id:#06x}] [from-{mode}] [{pkt_id:#06x}] fragment {frag_id}/{frag_total}: {err}",
                    mode = self.udp_forward_mode,
                    frag_id = frag_id + 1,
                );
                return;
            }
        };

        let process = async {
            log::info!(
                "[packet] [{assoc_id:#06x}] [from-{mode}] [{pkt_id:#06x}] to {src_addr}",
                mode = self.udp_forward_mode,
                src_addr = addr,
            );

            let Some(local_addr) = self.local.resolve().await?.next() else {
                return Err(Error::from(IoError::new(
                    ErrorKind::NotFound,
                    "no address resolved",
                )));
            };

            let session = match self.udp_sessions.lock().entry(assoc_id) {
                Entry::Occupied(entry) => entry.get().clone(),
                Entry::Vacant(entry) => {
                    let session = UdpSession::new(
                        self.clone(),
                        assoc_id,
                        self.max_packet_size,
                        self.udp_timeout,
                        local_addr,
                        addr.clone(),
                        self.proxy_protocol,
                    )?;
                    entry.insert(session.clone());
                    session
                }
            };

            session.send(pkt).await
        };

        if let Err(err) = process.await {
            log::warn!(
                "[packet] [{assoc_id:#06x}] [from-{mode}] [{pkt_id:#06x}] from {src_addr}: {err}",
                mode = self.udp_forward_mode,
                src_addr = addr,
            );
        }
    }

    pub async fn handle_dissociate(&self, assoc_id: u16) {
        log::info!("[dissociate] [{assoc_id:#06x}]");

        if let Some(session) = self.udp_sessions.lock().remove(&assoc_id) {
            session.close();
        }
    }

    pub async fn forward_packet(self, pkt: Bytes, addr: Address, assoc_id: u16) {
        let addr_display = addr.to_string();

        log::info!(
            "[packet] [{assoc_id:#06x}] [to-{mode}] to {dst_addr}",
            mode = self.udp_forward_mode,
            dst_addr = addr_display,
        );

        let res = match self.udp_forward_mode {
            UdpForwardMode::Native => self.model.packet_native(pkt, addr, assoc_id),
            UdpForwardMode::Quic => self.model.packet_quic(pkt, addr, assoc_id).await,
        };

        if let Err(err) = res {
            log::warn!(
                "[packet] [{assoc_id:#06x}] [to-{mode}] to {dst_addr}: {err}",
                mode = self.udp_forward_mode,
                dst_addr = addr_display,
            );
        }
    }
}
