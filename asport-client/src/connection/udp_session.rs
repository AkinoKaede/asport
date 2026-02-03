use std::{
    io::Error as IoError,
    net::{IpAddr, Ipv6Addr, SocketAddr, UdpSocket as StdUdpSocket},
    sync::{atomic::Ordering, Arc},
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
use asport_common::buffer_pool::BufferPool;

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
    // Buffer pool for reducing allocations
    buffer_pool: BufferPool,
    // Track update failures to avoid blocking
    update_failed: std::sync::atomic::AtomicBool,
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
            conn: conn.clone(),
            assoc_id,
            socket,
            max_pkt_size,
            local,
            proxy_protocol,
            remote: remote_socket_address,
            close: Mutex::new(Some(close_tx)),
            update: update_tx,
            buffer_pool: conn.buffer_pool.clone(),
            update_failed: std::sync::atomic::AtomicBool::new(false),
        }));

        let session_listening = session.clone();

        let listen = async move {
            let mut consecutive_errors = 0u32;
            const MAX_CONSECUTIVE_ERRORS: u32 = 10;

            loop {
                let pkt = match session_listening.recv().await {
                    Ok(res) => {
                        consecutive_errors = 0; // Reset error count on success
                        res
                    }
                    Err(err) => {
                        consecutive_errors += 1;
                        log::warn!(
                            "[packet] [{assoc_id:#06x}] outbound listening error (attempt {consecutive_errors}/{MAX_CONSECUTIVE_ERRORS}): {err}",
                        );

                        if consecutive_errors >= MAX_CONSECUTIVE_ERRORS {
                            log::error!(
                                "[packet] [{assoc_id:#06x}] Too many consecutive errors, closing session"
                            );
                            break;
                        }

                        // Exponential backoff for errors
                        let backoff_ms =
                            std::cmp::min(100 * (1 << consecutive_errors.min(6)), 5000);
                        time::sleep(Duration::from_millis(backoff_ms as u64)).await;
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

        // GC like NAT table with improved activity tracking
        // If this session is inactive, close itself.
        let gc_session = session.clone();
        tokio::spawn(async move {
            let mut activity_count = 0u32;
            let check_interval = Duration::from_secs(std::cmp::max(udp_timeout.as_secs() / 10, 1));

            loop {
                tokio::select! {
                    Some(_) = update_rx.recv() => {
                        activity_count += 1;

                        // Batch drain the channel to avoid excessive wake-ups
                        let mut batch_count = 1;
                        while update_rx.try_recv().is_ok() && batch_count < 100 {
                            batch_count += 1;
                        }
                        activity_count += batch_count - 1;
                    },
                    _ = time::sleep(check_interval) => {
                        if activity_count == 0 {
                            log::debug!(
                                "UDP session [{assoc_id:#06x}] timeout (no activity for {timeout}s)",
                                timeout = udp_timeout.as_secs()
                            );

                            if let Some(session) = gc_session.0.conn.udp_sessions.lock().remove(&assoc_id) {
                                session.close();
                            }

                            return;
                        }

                        // Reset activity count for next period
                        activity_count = 0;
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
        let packet = if matches!(self.0.proxy_protocol, ProxyProtocol::V2) {
            let addresses = union_proxy_protocol_addresses(self.0.remote, addr);

            let addresses = addresses.ok_or(Error::MissingAddress)?;

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

        // Convert IPv4 to IPv6-mapped address since socket is bound to [::]
        let target_addr = match addr {
            SocketAddr::V4(v4) => {
                SocketAddr::new(IpAddr::from(v4.ip().to_ipv6_mapped()), v4.port())
            }
            addr => addr,
        };

        self.0.socket.send_to(&packet, target_addr).await?;
        self.update().await;

        Ok(())
    }

    async fn recv(&self) -> Result<Bytes, IoError> {
        self.recv_from().await.map(|(pkt, _)| pkt)
    }

    async fn recv_from(&self) -> Result<(Bytes, SocketAddr), IoError> {
        // Get buffer from pool
        let mut buffer = self.0.buffer_pool.get();

        // Ensure buffer has adequate capacity
        if buffer.capacity() < self.0.max_pkt_size {
            buffer.reserve(self.0.max_pkt_size - buffer.capacity());
        }

        // Resize buffer to max capacity for receiving
        buffer.resize(self.0.max_pkt_size, 0);

        let (n, addr) = self.0.socket.recv_from(&mut buffer).await?;

        // Create Bytes from the received data
        let data = Bytes::copy_from_slice(&buffer[..n]);

        // Return buffer to pool
        self.0.buffer_pool.put(buffer);

        self.update().await;

        Ok((data, addr))
    }

    async fn update(&self) {
        // Skip update if previous updates have failed to avoid blocking
        if self.0.update_failed.load(Ordering::Relaxed) {
            return;
        }

        if self.0.update.try_send(()).is_err() {
            // Mark update as failed and log once
            if !self.0.update_failed.swap(true, Ordering::Relaxed) {
                log::debug!(
                    "[packet] [{assoc_id:#06x}] Update channel full, disabling further updates",
                    assoc_id = self.0.assoc_id
                );
            }
        }
    }

    pub fn close(&self) {
        let _ = self.0.close.lock().take().unwrap().send(());
    }
}
