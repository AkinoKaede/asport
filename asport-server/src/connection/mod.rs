use std::{
    collections::HashMap,
    sync::{atomic::AtomicU32, Arc},
    time::Duration,
};

use crossbeam_utils::atomic::AtomicCell;
use quinn::{Connecting, Connection as QuinnConnection, VarInt};
use register_count::Counter;
use tokio::{net::TcpListener, sync::Mutex, time};
use uuid::Uuid;

use asport::{Flags, ServerHello};
use asport_quinn::{side, ClientHello, Connection as Model};

use crate::{
    error::Error,
    utils::{self, Network, RemoteConfiguredFlgas, UdpForwardMode, User},
};

use self::{authenticated::Authenticated, udp_sessions::UdpSessions};

mod authenticated;
mod handle_bind;
mod handle_stream;
mod handle_task;
mod udp_sessions;

pub const ERROR_CODE: VarInt = VarInt::from_u32(0);
pub const DEFAULT_CONCURRENT_STREAMS: u32 = 32;

#[derive(Clone)]
pub struct Connection {
    inner: QuinnConnection,
    model: Model<side::Server>,
    users: Arc<HashMap<Uuid, User>>,
    auth: Authenticated,
    udp_forward_mode: Arc<AtomicCell<Option<UdpForwardMode>>>,

    udp_sessions: Arc<Mutex<Option<UdpSessions>>>,

    task_negotiation_timeout: Duration,
    authentication_failed_reply: bool,
    max_packet_size: usize,
    buffer_pool_size: usize,
    udp_session_timeout: Duration,

    remote_uni_stream_cnt: Counter,
    remote_bi_stream_cnt: Counter,
    max_concurrent_uni_streams: Arc<AtomicU32>,
    max_concurrent_bi_streams: Arc<AtomicU32>,
}

impl Connection {
    fn new(
        conn: QuinnConnection,
        users: Arc<HashMap<Uuid, User>>,
        task_negotiation_timeout: Duration,
        authentication_failed_reply: bool,
        max_packet_size: usize,
        buffer_pool_size: usize,
        udp_session_timeout: Duration,
    ) -> Self {
        Self {
            inner: conn.clone(),
            model: Model::<side::Server>::new(conn),
            users,
            auth: Authenticated::new(),
            udp_forward_mode: Arc::new(AtomicCell::new(None)),
            udp_sessions: Arc::new(Mutex::new(None)),
            task_negotiation_timeout,
            authentication_failed_reply,
            max_packet_size,
            buffer_pool_size,
            udp_session_timeout,
            remote_uni_stream_cnt: Counter::new(),
            remote_bi_stream_cnt: Counter::new(),
            max_concurrent_uni_streams: Arc::new(AtomicU32::new(DEFAULT_CONCURRENT_STREAMS)),
            max_concurrent_bi_streams: Arc::new(AtomicU32::new(DEFAULT_CONCURRENT_STREAMS)),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn handle(
        conn: Connecting,
        users: Arc<HashMap<Uuid, User>>,
        zero_rtt_handshake: bool,
        auth_timeout: Duration,
        task_negotiation_timeout: Duration,
        authentication_failed_reply: bool,
        max_packet_size: usize,
        buffer_pool_size: usize,
        udp_session_timeout: Duration,
    ) {
        let addr = conn.remote_address();

        let init = async {
            let conn = if zero_rtt_handshake {
                match conn.into_0rtt() {
                    Ok((conn, _)) => conn,
                    Err(conn) => conn.await?,
                }
            } else {
                conn.await?
            };

            Ok::<_, Error>(Self::new(
                conn,
                users,
                task_negotiation_timeout,
                authentication_failed_reply,
                max_packet_size,
                buffer_pool_size,
                udp_session_timeout,
            ))
        };

        match init.await {
            Ok(conn) => {
                log::info!(
                    "[{id:#010x}] [{addr}] [{user}] connection established",
                    id = conn.id(),
                    user = conn.auth,
                );

                tokio::spawn(conn.clone().timeout_handshake(auth_timeout));
                tokio::spawn(conn.clone().release_udp_sessions());

                loop {
                    if conn.is_closed() {
                        break;
                    }

                    let handle_incoming = async {
                        tokio::select! {
                            res = conn.inner.accept_uni() =>
                                tokio::spawn(conn.clone().handle_uni_stream(res?, conn.remote_uni_stream_cnt.reg())),
                            res = conn.inner.accept_bi() =>
                                tokio::spawn(conn.clone().handle_bi_stream(res?, conn.remote_bi_stream_cnt.reg())),
                            res = conn.inner.read_datagram() =>
                                tokio::spawn(conn.clone().handle_datagram(res?)),
                        };

                        Ok::<_, Error>(())
                    };

                    match handle_incoming.await {
                        Ok(()) => {}
                        Err(err) if err.is_trivial() => {
                            log::debug!(
                                "[{id:#010x}] [{addr}] [{user}] {err}",
                                id = conn.id(),
                                user = conn.auth,
                            );
                        }
                        Err(err) => log::warn!(
                            "[{id:#010x}] [{addr}] [{user}] connection error: {err}",
                            id = conn.id(),
                            user = conn.auth,
                        ),
                    }
                }
            }
            Err(err) if err.is_trivial() => {
                log::debug!(
                    "[{id:#010x}] [{addr}] [unauthenticated] {err}",
                    id = u32::MAX,
                );
            }
            Err(err) => {
                log::warn!(
                    "[{id:#010x}] [{addr}] [unauthenticated] {err}",
                    id = u32::MAX,
                )
            }
        }
    }

    async fn handshake(&self, hello: &ClientHello) -> Result<(), Error> {
        if self.auth.get().is_some() {
            return Err(Error::DuplicatedHello);
        }

        let (network, udp_forward_mode) =
            <Flags as TryInto<RemoteConfiguredFlgas>>::try_into(hello.flags())?.into();
        self.udp_forward_mode.store(Some(udp_forward_mode));

        let res = self.process_handshake(hello, network).await;

        match res {
            Ok(listen_port) => {
                self.server_hello(ServerHello::Success(listen_port)).await;
                self.auth.set(hello.uuid(), listen_port);
            }
            Err(Error::AuthFailed(_)) => {
                if self.authentication_failed_reply {
                    self.server_hello(ServerHello::AuthFailed).await;
                }
            }
            Err(Error::BindFailed) => self.server_hello(ServerHello::BindFailed).await,
            Err(Error::PortDenied) => self.server_hello(ServerHello::PortDenied).await,
            Err(Error::NetworkDenied(_)) => self.server_hello(ServerHello::NetworkDenied).await,
            _ => unreachable!(),
        };

        res.map(|_| ())
    }

    async fn process_handshake(&self, hello: &ClientHello, network: Network) -> Result<u16, Error> {
        let user = self
            .users
            .get(&hello.uuid())
            .ok_or(Error::AuthFailed(hello.uuid()))?;
        if !hello.validate(user.password()) {
            return Err(Error::AuthFailed(hello.uuid()));
        }

        let range = hello.expected_port_range();

        let ports = user
            .allow_ports()
            .into_iter()
            .filter(|port| range.contains(port))
            .collect();

        let network = utils::merge_network(*user.allow_network(), network)?;

        self.bind(user.listen_ip(), ports, user.only_v6(), &network)
            .await
    }

    async fn handle_tcp_listener(self, listener: TcpListener) {
        tokio::spawn(async move {
            // Prevent send `Connect` before `ServerHello`
            // If not, can cause client to close connection, and it can be used for DoS attack
            self.auth.clone().await;

            loop {
                tokio::select! {
                    res = listener.accept() => {
                            tokio::spawn(self.clone().forward_tcp(res?));
                         },
                    _ = self.closed() => {
                        return Ok::<(), Error>(()); // Connection closed
                    }
                };
            }
        });
    }

    async fn release_udp_sessions(self) {
        self.closed().await;

        let mut udp_sessions = self.udp_sessions.lock().await;
        if let Some(udp_sessions) = udp_sessions.as_mut() {
            udp_sessions.close();
        }

        *udp_sessions = None;
    }

    async fn timeout_handshake(self, timeout: Duration) {
        time::sleep(timeout).await;

        if self.auth.get().is_none() {
            log::warn!(
                "[{id:#010x}] [{addr}] [unauthenticated] [authenticate] timeout",
                id = self.id(),
                addr = self.inner.remote_address(),
            );
            self.close();
        }
    }

    async fn closed(&self) {
        self.inner.closed().await;
    }

    fn id(&self) -> u32 {
        self.inner.stable_id() as u32
    }

    fn is_closed(&self) -> bool {
        self.inner.close_reason().is_some()
    }

    fn close(&self) {
        self.inner.close(ERROR_CODE, &[]);
    }
}
