use std::{
    collections::HashMap,
    io::Error as IoError,
    net::{IpAddr, SocketAddr},
    sync::{
        atomic::{AtomicU16, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use bytes::Bytes;
use parking_lot::Mutex;
use tokio::{
    net::UdpSocket,
    sync::oneshot::{self, Sender},
    time::{interval, Duration as TokioDuration},
};

use asport::Address;
use asport_common::buffer_pool::BufferPool;

use crate::error::Error;

use super::Connection;

#[derive(Clone)]
pub struct UdpSessions(Arc<UdpSessionsInner>);

struct UdpSessionsInner {
    conn: Connection,
    socket: UdpSocket,
    local_addr: SocketAddr,
    max_pkt_size: usize,
    buffer_pool: BufferPool,
    assoc_id_addr_map: Arc<Mutex<bimap::BiMap<u16, SocketAddr>>>,
    // Track last activity time for each association ID
    session_last_activity: Arc<Mutex<HashMap<u16, Instant>>>,
    // Session timeout duration (default 5 minutes)
    session_timeout: Duration,
    close: Mutex<Option<Sender<()>>>,
}

impl UdpSessions {
    pub fn with_timeout(
        conn: Connection,
        socket: UdpSocket,
        max_pkt_size: usize,
        buffer_pool_size: usize,
        session_timeout: Duration,
    ) -> Self {
        let (tx, rx) = oneshot::channel();
        let assoc_id_addr_map = Arc::new(Mutex::new(bimap::BiMap::new()));
        let session_last_activity = Arc::new(Mutex::new(HashMap::new()));
        let assoc_id_addr_map_listening = assoc_id_addr_map.clone();
        let session_last_activity_listening = session_last_activity.clone();

        let local_addr = socket.local_addr().unwrap();

        let sessions = Self(Arc::new(UdpSessionsInner {
            conn,
            socket,
            local_addr,
            max_pkt_size,
            buffer_pool: BufferPool::new(max_pkt_size, buffer_pool_size),
            assoc_id_addr_map,
            session_last_activity,
            session_timeout,
            close: Mutex::new(Some(tx)),
        }));

        let session_listening = sessions.clone();
        let session_gc = sessions.clone();

        let listen = async move {
            // Prevent send `Packet` before `ServerHello`
            // If not, can cause client to close connection, and it can be used for DoS attack
            session_listening.0.conn.auth.clone().await;

            let next_assoc_id = AtomicU16::new(1); // Start from 1, reserve 0 for special use

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
                    Some(assoc_id) => {
                        let assoc_id = *assoc_id;
                        // Update last activity time for existing session
                        session_last_activity_listening
                            .lock()
                            .insert(assoc_id, Instant::now());
                        assoc_id
                    }
                    None => {
                        // Find a free association ID with collision detection
                        let mut attempts = 0;
                        let mut assoc_id = next_assoc_id.fetch_add(1, Ordering::Relaxed);

                        // Wrap around from u16::MAX back to 1 (reserve 0)
                        if assoc_id == 0 {
                            assoc_id = 1;
                            next_assoc_id.store(2, Ordering::Relaxed);
                        }

                        // Handle collision by finding next free ID
                        while lock.contains_left(&assoc_id) && attempts < u16::MAX {
                            assoc_id = next_assoc_id.fetch_add(1, Ordering::Relaxed);
                            if assoc_id == 0 {
                                assoc_id = 1;
                                next_assoc_id.store(2, Ordering::Relaxed);
                            }
                            attempts += 1;
                        }

                        if attempts == u16::MAX {
                            log::error!(
                                "[{id:#010x}] [{addr}] [{auth}] No available association IDs",
                                id = session_listening.0.conn.id(),
                                addr = session_listening.0.conn.inner.remote_address(),
                                auth = session_listening.0.conn.auth,
                            );
                            continue;
                        }

                        // Check if we're reusing a previous association ID
                        if lock.remove_by_left(&assoc_id).is_some() {
                            dissociate_before_forward = true;
                        }

                        // Record activity time for new session
                        session_last_activity_listening
                            .lock()
                            .insert(assoc_id, Instant::now());

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

        // Spawn garbage collection task
        let gc_task = async move {
            let mut gc_interval = interval(TokioDuration::from_secs(60)); // Check every minute
            let mut error_count = 0;

            loop {
                gc_interval.tick().await;
                if let Err(err) = tokio::time::timeout(
                    TokioDuration::from_secs(30),
                    session_gc.cleanup_expired_sessions(),
                )
                .await
                {
                    error_count += 1;
                    log::warn!(
                        "[{id:#010x}] [{addr}] [{auth}] GC task timeout or error (count: {error_count}): {err}",
                        id = session_gc.0.conn.id(),
                        addr = session_gc.0.conn.inner.remote_address(),
                        auth = session_gc.0.conn.auth,
                    );

                    // If too many consecutive errors, break the GC loop
                    if error_count > 5 {
                        log::error!(
                            "[{id:#010x}] [{addr}] [{auth}] GC task failed too many times, stopping cleanup",
                            id = session_gc.0.conn.id(),
                            addr = session_gc.0.conn.inner.remote_address(),
                            auth = session_gc.0.conn.auth,
                        );
                        break;
                    }
                } else {
                    error_count = 0; // Reset error count on successful cleanup
                }
            }
        };

        tokio::spawn(async move {
            tokio::select! {
                _ = listen => unreachable!(),
                _ = gc_task => unreachable!(),
                _ = rx => {},
            }
        });

        sessions
    }

    pub async fn send_to(&self, pkt: Bytes, addr: SocketAddr) -> Result<(), Error> {
        // map ipv4 to ipv6-mapped-ipv4
        let addr = match (addr, self.0.local_addr) {
            (SocketAddr::V4(v4), SocketAddr::V6(_)) => {
                SocketAddr::new(IpAddr::from(v4.ip().to_ipv6_mapped()), v4.port())
            }
            (addr, _) => addr,
        };

        self.0.socket.send_to(&pkt, addr).await?;
        Ok(())
    }

    async fn recv_from(&self) -> Result<(Bytes, SocketAddr), IoError> {
        // Get buffer from pool
        let mut buf = self.0.buffer_pool.get();

        // Ensure buffer has adequate capacity
        if buf.capacity() < self.0.max_pkt_size {
            buf.reserve(self.0.max_pkt_size - buf.capacity());
        }

        // Resize buffer to max capacity for receiving
        buf.resize(self.0.max_pkt_size, 0);

        let (n, addr) = self.0.socket.recv_from(&mut buf).await?;

        // Create Bytes from the received data
        let data = Bytes::copy_from_slice(&buf[..n]);

        // Return buffer to pool
        self.0.buffer_pool.put(buf);

        Ok((data, addr))
    }

    pub fn validate(&self, assoc_id: u16, socket_addr: SocketAddr) -> bool {
        let mut activity_lock = self.0.session_last_activity.lock();
        let is_valid = matches!(self.0.assoc_id_addr_map.lock().get_by_left(&assoc_id), Some(addr) if *addr == socket_addr);

        if is_valid {
            // Update activity time on validation
            activity_lock.insert(assoc_id, Instant::now());
        }

        is_valid
    }

    async fn cleanup_expired_sessions(&self) {
        let now = Instant::now();
        let timeout = self.0.session_timeout;
        let mut expired_assoc_ids = Vec::new();

        // Find expired sessions
        {
            let activity_lock = self.0.session_last_activity.lock();
            for (&assoc_id, &last_activity) in activity_lock.iter() {
                if now.duration_since(last_activity) > timeout {
                    expired_assoc_ids.push(assoc_id);
                }
            }
        }

        // Clean up expired sessions
        if !expired_assoc_ids.is_empty() {
            log::debug!(
                "[{id:#010x}] [{addr}] [{auth}] Cleaning up {} expired UDP sessions",
                expired_assoc_ids.len(),
                id = self.0.conn.id(),
                addr = self.0.conn.inner.remote_address(),
                auth = self.0.conn.auth,
            );

            for assoc_id in expired_assoc_ids {
                // Send dissociate command to client
                if let Err(err) = self.0.conn.dissociate(assoc_id).await {
                    log::warn!(
                        "[{id:#010x}] [{addr}] [{auth}] Failed to dissociate expired session {assoc_id:#06x}: {err}",
                        id = self.0.conn.id(),
                        addr = self.0.conn.inner.remote_address(),
                        auth = self.0.conn.auth,
                    );
                }

                // Remove from internal maps after awaiting
                {
                    let mut addr_map_lock = self.0.assoc_id_addr_map.lock();
                    let mut activity_lock = self.0.session_last_activity.lock();
                    addr_map_lock.remove_by_left(&assoc_id);
                    activity_lock.remove(&assoc_id);
                }
            }
        }
    }

    pub fn close(&self) {
        let _ = self.0.close.lock().take().unwrap().send(());
    }
}
