use std::{
    io::Error as IoError,
    net::{IpAddr, Ipv6Addr, SocketAddr, UdpSocket as StdUdpSocket},
    sync::Arc,
    time::Duration,
};

use bytes::{BufMut, Bytes, BytesMut};
use parking_lot::Mutex;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::{
    net::UdpSocket,
    sync::{
        mpsc::{self, Sender as MpscSender},
        oneshot::{self, Sender as OneshotSender},
    },
    time,
};

use asport::Address;

use crate::error::Error;
use crate::utils::{union_proxy_protocol_addresses, ProxyProtocol};

use super::Connection;

#[derive(Clone)]
pub struct UdpSession(Arc<UdpSessionInner>);

struct UdpSessionInner {
    assoc_id: u16,
    conn: Connection,
    socket: UdpSocket,
    max_pkt_size: usize,
    local: SocketAddr,
    remote: Option<SocketAddr>,
    proxy_protocol: ProxyProtocol,
    update: MpscSender<()>,
    close: Mutex<Option<OneshotSender<()>>>,
}

impl UdpSession {
    pub fn new(
        conn: Connection,
        assoc_id: u16,
        max_pkt_size: usize,
        udp_timeout: Duration,
        local: SocketAddr,
        remote: Address,
        proxy_protocol: ProxyProtocol,
    ) -> Result<Self, Error> {
        let socket = {
            let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))
                .map_err(|err| Error::Socket("failed to create UDP associate IPv6 socket", err))?;

            socket.set_nonblocking(true).map_err(|err| {
                Error::Socket(
                    "failed setting UDP associate IPv6 socket as non-blocking",
                    err,
                )
            })?;

            socket
                .bind(&SockAddr::from(SocketAddr::from((
                    Ipv6Addr::UNSPECIFIED,
                    0,
                ))))
                .map_err(|err| Error::Socket("failed to bind UDP associate IPv6 socket", err))?;
            UdpSocket::from_std(StdUdpSocket::from(socket))?
        };

        let (close_tx, close_rx) = oneshot::channel();

        let (update_tx, mut update_rx) = mpsc::channel(1);

        let remote_socket_address = match remote {
            Address::SocketAddress(addr) => Some(addr),
            Address::None => None,
        };

        let session = Self(Arc::new(UdpSessionInner {
            conn,
            assoc_id,
            socket,
            max_pkt_size,
            local,
            proxy_protocol,
            remote: remote_socket_address,
            close: Mutex::new(Some(close_tx)),
            update: update_tx,
        }));

        let session_listening = session.clone();

        let listen = async move {
            loop {
                let pkt = match session_listening.recv().await {
                    Ok(res) => res,
                    Err(err) => {
                        log::warn!("[packet] [{assoc_id:#06x}] outbound listening error: {err}",);
                        continue;
                    }
                };

                tokio::spawn(session_listening.0.conn.clone().forward_packet(
                    pkt,
                    remote.clone(),
                    session_listening.0.assoc_id,
                ));
            }
        };

        tokio::spawn(async move {
            tokio::select! {
                _ = listen => unreachable!(),
                _ = close_rx => {},
            }
        });

        // GC like NAT table
        // If this session is inactive, close itself.
        let gc_session = session.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                     Some(_) = update_rx.recv() => {},
                     _ = time::sleep(udp_timeout) => {
                         log::debug!("UDP session [{assoc_id:#06x}] timeout");

                         if let Some(session)= gc_session.0.conn.udp_sessions.lock().remove(&assoc_id) {
                             session.close();
                         };

                         return;
                    },
                }
            }
        });

        Ok(session)
    }

    pub async fn send(&self, pkt: Bytes) -> Result<(), Error> {
        self.send_to(pkt, self.0.local).await
    }

    pub async fn send_to(&self, pkt: Bytes, addr: SocketAddr) -> Result<(), Error> {
        let addresses = union_proxy_protocol_addresses(self.0.remote, addr);

        let packet = if matches!(self.0.proxy_protocol, ProxyProtocol::V2) {
            let addresses = if let Some(addresses) = addresses {
                addresses
            } else {
                return Err(Error::MissingAddress);
            };

            let v2 = ppp::v2::Builder::with_addresses(
                ppp::v2::Version::Two | ppp::v2::Command::Proxy,
                ppp::v2::Protocol::Datagram,
                addresses,
            )
            .build()
            .unwrap();

            let mut buf = BytesMut::with_capacity(v2.len() + pkt.len());
            buf.put(v2.as_slice());
            buf.put(pkt);
            buf.freeze()
        } else {
            pkt
        };

        // Because self.0.socket is bind on [::], we need to convert the IPv4 address to IPv6.
        let addr = match addr {
            SocketAddr::V4(v4) => {
                SocketAddr::new(IpAddr::from(v4.ip().to_ipv6_mapped()), v4.port())
            }
            addr => addr,
        };

        self.0.socket.send_to(&packet, addr).await?;

        self.update().await;

        Ok(())
    }

    async fn recv(&self) -> Result<Bytes, IoError> {
        self.recv_from().await.map(|(pkt, _)| pkt)
    }

    async fn recv_from(&self) -> Result<(Bytes, SocketAddr), IoError> {
        let mut buf = vec![0u8; self.0.max_pkt_size];
        let (n, addr) = self.0.socket.recv_from(&mut buf).await?;
        buf.truncate(n);

        self.update().await;

        Ok((Bytes::from(buf), addr))
    }

    async fn update(&self) {
        self.0.update.send(()).await.unwrap();
    }

    pub fn close(&self) {
        let _ = self.0.close.lock().take().unwrap().send(());
    }
}
