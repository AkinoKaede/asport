use std::{
    io::Error as IoError,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicU16, Ordering},
    },
};

use bytes::Bytes;
use parking_lot::Mutex;
use tokio::{
    net::UdpSocket,
    sync::oneshot::{self, Sender},
};

use asport::Address;

use crate::error::Error;

use super::Connection;

#[derive(Clone)]
pub struct UdpSessions(Arc<UdpSessionsInner>);

struct UdpSessionsInner {
    conn: Connection,
    socket: UdpSocket,
    local_addr: SocketAddr,
    max_pkt_size: usize,
    assoc_id_addr_map: Arc<Mutex<bimap::BiMap<u16, SocketAddr>>>,
    close: Mutex<Option<Sender<()>>>,
}

impl UdpSessions {
    pub fn new(conn: Connection, socket: UdpSocket, max_pkt_size: usize) -> Self {
        let (tx, rx) = oneshot::channel();
        let assoc_id_addr_map = Arc::new(Mutex::new(bimap::BiMap::new()));
        let assoc_id_addr_map_listening = assoc_id_addr_map.clone();

        let local_addr = socket.local_addr().unwrap();

        let sessions = Self(Arc::new(UdpSessionsInner {
            conn,
            socket,
            local_addr,
            max_pkt_size,
            assoc_id_addr_map,
            close: Mutex::new(Some(tx)),
        }));

        let session_listening = sessions.clone();


        let listen = async move {
            // Prevent send `Packet` before `ServerHello`
            // If not, can cause client to close connection, and it can be used for DoS attack
            session_listening.0.conn.auth.clone().await;

            let next_assoc_id = AtomicU16::new(0);

            loop {
                let (pkt, addr) = match session_listening.recv_from().await {
                    Ok(res) => res,
                    Err(err) => {
                        log::warn!(
                            "[{id:#010x}] [{addr}] [{auth}] [packet] outbound listening error: {err}",
                            id = session_listening.0.conn.id(),
                            addr = session_listening.0.conn.inner.remote_address(),
                            auth = session_listening.0.conn.auth,
                        );
                        continue;
                    }
                };

                let mut dissociate_before_forward = false;
                let mut lock = assoc_id_addr_map_listening.lock();
                let assoc_id = match lock.get_by_right(&addr) {
                    Some(assoc_id) => *assoc_id,
                    None => {
                        let assoc_id = next_assoc_id.fetch_add(1, Ordering::Relaxed);

                        if let Some(_) = lock.remove_by_left(&assoc_id) {
                            dissociate_before_forward = true;
                        }

                        assoc_id
                    }
                };

                lock.insert(assoc_id, addr);

                tokio::spawn(session_listening.0.conn.clone().forward_packet(
                    pkt,
                    Address::SocketAddress(addr),
                    assoc_id,
                    dissociate_before_forward,
                ));
            }
        };

        tokio::spawn(async move {
            tokio::select! {
                _ = listen => unreachable!(),
                _ = rx => {},
            }
        });

        sessions
    }


    pub async fn send_to(&self, pkt: Bytes, addr: SocketAddr) -> Result<(), Error> {
        // map ipv4 to ipv6-mapped-ipv4
        let addr = match (addr, self.0.local_addr) {
            (SocketAddr::V4(v4), SocketAddr::V6(_)) => SocketAddr::new(IpAddr::from(v4.ip().to_ipv6_mapped()), v4.port()),
            (addr, _) => addr,
        };

        self.0.socket.send_to(&pkt, addr).await?;
        Ok(())
    }

    async fn recv_from(&self) -> Result<(Bytes, SocketAddr), IoError> {
        let mut buf = vec![0u8; self.0.max_pkt_size];
        let (n, addr) = self.0.socket.recv_from(&mut buf).await?;
        buf.truncate(n);
        Ok((Bytes::from(buf), addr))
    }

    pub fn validate(&self, assoc_id: u16, socket_addr: SocketAddr) -> bool {
        matches!(self.0.assoc_id_addr_map.lock().get_by_left(&assoc_id), Some(addr) if *addr == socket_addr)
    }

    pub fn close(&self) {
        let _ = self.0.close.lock().take().unwrap().send(());
    }
}