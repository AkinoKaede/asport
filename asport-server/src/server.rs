use std::{
    collections::HashMap,
    net::{SocketAddr, UdpSocket as StdUdpSocket},
    sync::Arc,
    time::Duration,
};

use quinn::{congestion::{BbrConfig, CubicConfig, NewRenoConfig}, Endpoint, EndpointConfig,
            IdleTimeout, ServerConfig, TokioRuntime, TransportConfig, VarInt};
use quinn::crypto::rustls::QuicServerConfig;
use rustls::ServerConfig as RustlsServerConfig;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use uuid::Uuid;

use crate::{
    config::Config,
    connection::{Connection, DEFAULT_CONCURRENT_STREAMS},
    error::Error,
    utils::{CongestionControl, User},
};

pub struct Server {
    ep: Endpoint,
    users: Arc<HashMap<Uuid, User>>,
    zero_rtt_handshake: bool,
    hello_timeout: Duration,
    task_negotiation_timeout: Duration,
    authentication_failed_reply: bool,
    max_packet_size: usize,
}

impl Server {
    pub fn init(cfg: Config) -> Result<Self, Error> {
        // CryptoProvider::get_default();
        let mut crypto = RustlsServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cfg.certificate, cfg.private_key)?;

        crypto.alpn_protocols = cfg.alpn;
        crypto.max_early_data_size = u32::MAX;
        crypto.send_half_rtt_data = cfg.zero_rtt_handshake;


        let mut config = ServerConfig::with_crypto(Arc::new(
            QuicServerConfig::try_from(crypto)?));
        let mut tp_cfg = TransportConfig::default();

        tp_cfg
            .max_concurrent_bidi_streams(VarInt::from(DEFAULT_CONCURRENT_STREAMS))
            .max_concurrent_uni_streams(VarInt::from(DEFAULT_CONCURRENT_STREAMS))
            .send_window(cfg.send_window)
            .stream_receive_window(VarInt::from_u32(cfg.receive_window))
            .max_idle_timeout(Some(
                IdleTimeout::try_from(cfg.max_idle_time).map_err(|_| Error::InvalidMaxIdleTime)?,
            ));

        match cfg.congestion_control {
            CongestionControl::Cubic => {
                tp_cfg.congestion_controller_factory(Arc::new(CubicConfig::default()))
            }
            CongestionControl::NewReno => {
                tp_cfg.congestion_controller_factory(Arc::new(NewRenoConfig::default()))
            }
            CongestionControl::Bbr => {
                tp_cfg.congestion_controller_factory(Arc::new(BbrConfig::default()))
            }
        };

        config.transport_config(Arc::new(tp_cfg));

        let mut users = HashMap::new();
        for proxy in cfg.proxies {
            for (uuid, password) in proxy.users {
                users.insert(uuid, User::new(password, proxy.bind_ip, proxy.allow_ports.clone(),
                                             proxy.only_v6, proxy.allow_network));
            }
        }


        let socket = {
            let domain = match cfg.server {
                SocketAddr::V4(_) => Domain::IPV4,
                SocketAddr::V6(_) => Domain::IPV6,
            };

            let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))
                .map_err(|err| Error::Socket("failed to create endpoint UDP socket", err))?;


            if let Some(only_v6) = cfg.only_v6 {
                socket.set_only_v6(only_v6).map_err(|err| {
                    Error::Socket("endpoint dual-stack socket setting error", err)
                })?;
            }

            socket
                .bind(&SockAddr::from(cfg.server))
                .map_err(|err| Error::Socket("failed to bind endpoint UDP socket", err))?;

            StdUdpSocket::from(socket)
        };


        let ep = Endpoint::new(
            EndpointConfig::default(),
            Some(config),
            socket,
            Arc::new(TokioRuntime),
        )?;

        Ok(Self {
            ep,
            users: Arc::new(users),
            zero_rtt_handshake: cfg.zero_rtt_handshake,
            hello_timeout: cfg.handshake_timeout,
            task_negotiation_timeout: cfg.task_negotiation_timeout,
            authentication_failed_reply: cfg.authentication_failed_reply,
            max_packet_size: cfg.max_packet_size,
        })
    }

    pub async fn start(&self) {
        log::warn!(
            "Server started on {}",
            self.ep.local_addr().unwrap()
        );

        loop {
            let Some(incoming) = self.ep.accept().await else {
                return;
            };

            match incoming.accept() {
                Ok(conn) => {
                    tokio::spawn(Connection::handle(
                        conn,
                        self.users.clone(),
                        self.zero_rtt_handshake,
                        self.hello_timeout,
                        self.task_negotiation_timeout,
                        self.authentication_failed_reply,
                        self.max_packet_size,
                    ));
                }
                Err(err) => {
                    log::warn!("Failed to accept incoming connection: {}", err);
                }
            }
        }
    }
}