use std::{
    collections::HashMap,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket},
    ops::RangeInclusive,
    sync::{atomic::AtomicU32, Arc},
    time::Duration,
};

use crossbeam_utils::atomic::AtomicCell;
use once_cell::sync::OnceCell;
use parking_lot::Mutex;
use quinn::{
    congestion::{BbrConfig, CubicConfig, NewRenoConfig},
    crypto::rustls::QuicClientConfig,
    ClientConfig, Connection as QuinnConnection, Endpoint as QuinnEndpoint, EndpointConfig,
    TokioRuntime, TransportConfig, VarInt, ZeroRttAccepted,
};
use register_count::Counter;
use rustls::{
    client::danger,
    crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider},
    pki_types::{CertificateDer, ServerName, UnixTime},
    {ClientConfig as RustlsClientConfig, DigitallySignedStruct, SignatureScheme},
};

use tokio::{
    sync::{Mutex as AsyncMutex, OnceCell as AsyncOnceCell},
    time,
};
use uuid::Uuid;

use asport::ServerHello as ServerHelloHeader;
use asport_quinn::{side, Connection as Model, ServerHello};

use crate::{
    config::Config,
    error::Error,
    utils::{Address, CongestionControl, Network, ProxyProtocol, ServerAddress, UdpForwardMode},
};

use self::{authenticated::Authenticated, udp_session::UdpSession};

mod authenticated;
mod handle_stream;
mod handle_task;
mod udp_session;

static ENDPOINT: OnceCell<Mutex<Endpoint>> = OnceCell::new();
static CONNECTION: AsyncOnceCell<AsyncMutex<Connection>> = AsyncOnceCell::const_new();
static HEALTHY_CHECK: AtomicCell<Duration> = AtomicCell::new(Duration::from_secs(0));
static TIMEOUT: AtomicCell<Duration> = AtomicCell::new(Duration::from_secs(0));

pub const ERROR_CODE: VarInt = VarInt::from_u32(0);
const DEFAULT_CONCURRENT_STREAMS: u32 = 32;

#[derive(Clone)]
pub struct Connection {
    inner: QuinnConnection,
    model: Model<side::Client>,
    local: Address,
    uuid: Uuid,
    password: Arc<[u8]>,
    network: Network,
    udp_sessions: Arc<Mutex<HashMap<u16, UdpSession>>>,
    udp_timeout: Duration,
    udp_forward_mode: UdpForwardMode,
    expected_port_range: RangeInclusive<u16>,
    auth: Authenticated,
    task_negotiation_timeout: Duration,
    max_packet_size: usize,
    proxy_protocol: ProxyProtocol,
    remote_uni_stream_cnt: Counter,
    remote_bi_stream_cnt: Counter,
    max_concurrent_uni_streams: Arc<AtomicU32>,
    max_concurrent_bi_streams: Arc<AtomicU32>,
}

impl Connection {
    pub fn set_config(cfg: Config) -> Result<(), Error> {
        let mut crypto = RustlsClientConfig::builder()
            .with_root_certificates(cfg.certificates)
            .with_no_client_auth();

        if cfg.skip_cert_verification {
            crypto
                .dangerous()
                .set_certificate_verifier(SkipServerVerification::new());
        }

        crypto.alpn_protocols = cfg.alpn;
        crypto.enable_early_data = true;
        crypto.enable_sni = !cfg.disable_sni;

        let mut config = ClientConfig::new(Arc::new(QuicClientConfig::try_from(crypto)?));
        let mut tp_cfg = TransportConfig::default();

        tp_cfg
            .max_concurrent_bidi_streams(VarInt::from(DEFAULT_CONCURRENT_STREAMS))
            .max_concurrent_uni_streams(VarInt::from(DEFAULT_CONCURRENT_STREAMS))
            .send_window(cfg.send_window)
            .stream_receive_window(VarInt::from_u32(cfg.receive_window))
            .max_idle_timeout(None);

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

        // Try to create an IPv4 socket as the placeholder first, if it fails, try IPv6.
        let socket = UdpSocket::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))
            .or_else(|err| {
                UdpSocket::bind(SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))).map_err(|_| err)
            })
            .map_err(|err| Error::Socket("failed to create endpoint UDP socket", err))?;

        let mut ep = QuinnEndpoint::new(
            EndpointConfig::default(),
            None,
            socket,
            Arc::new(TokioRuntime),
        )?;

        ep.set_default_client_config(config);

        let ep = Endpoint {
            ep,
            server: ServerAddress::new(cfg.server, cfg.server_name),
            local: cfg.local,
            uuid: cfg.uuid,
            password: cfg.password,
            network: cfg.network,
            udp_forward_mode: cfg.udp_forward_mode,
            udp_timeout: cfg.udp_timeout,
            expected_port_range: cfg.expected_port_range,
            zero_rtt_handshake: cfg.zero_rtt_handshake,
            heartbeat: cfg.heartbeat,
            handshake_timeout: cfg.handshake_timeout,
            task_negotiation_timeout: cfg.task_negotiation_timeout,
            max_packet_size: cfg.max_packet_size,
            gc_interval: cfg.gc_interval,
            gc_lifetime: cfg.gc_lifetime,
            proxy_protocol: cfg.proxy_protocol,
        };

        ENDPOINT
            .set(Mutex::new(ep))
            .map_err(|_| "endpoint already initialized")
            .unwrap();

        HEALTHY_CHECK.store(cfg.healthy_check);
        TIMEOUT.store(cfg.timeout);

        Ok(())
    }

    pub async fn check() -> Result<(), Error> {
        let try_init_conn = async {
            ENDPOINT
                .get()
                .unwrap()
                .lock()
                .connect()
                .await
                .map(AsyncMutex::new)
        };

        let check_and_reconnect_conn = async {
            let mut conn = CONNECTION
                .get_or_try_init(|| try_init_conn)
                .await?
                .lock()
                .await;

            if conn.is_closed() {
                let new_conn = ENDPOINT.get().unwrap().lock().connect().await?;
                *conn = new_conn;
            }

            Ok::<_, Error>(())
        };

        time::timeout(TIMEOUT.load(), check_and_reconnect_conn)
            .await
            .map_err(|_| Error::Timeout)??;

        Ok(())
    }

    pub async fn start() {
        let mut interval = time::interval(HEALTHY_CHECK.load());

        loop {
            interval.tick().await;

            if let Err(err) = Self::check().await {
                log::warn!("[check] {err}", err = err);
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn new(
        conn: QuinnConnection,
        zero_rtt_accepted: Option<ZeroRttAccepted>,
        local: Address,
        uuid: Uuid,
        password: Arc<[u8]>,
        network: Network,
        udp_forward_mode: UdpForwardMode,
        udp_timeout: Duration,
        expected_port_range: RangeInclusive<u16>,
        heartbeat: Duration,
        handshake_timeout: Duration,
        task_negotiation_timeout: Duration,
        max_packet_size: usize,
        gc_interval: Duration,
        gc_lifetime: Duration,
        proxy_protocol: ProxyProtocol,
    ) -> Self {
        let conn = Self {
            inner: conn.clone(),
            model: Model::<side::Client>::new(conn),
            local,
            uuid,
            password,
            network,
            udp_sessions: Arc::new(Mutex::new(HashMap::new())),
            udp_forward_mode,
            udp_timeout,
            expected_port_range,
            auth: Authenticated::new(),
            task_negotiation_timeout,
            max_packet_size,
            proxy_protocol,
            remote_uni_stream_cnt: Counter::new(),
            remote_bi_stream_cnt: Counter::new(),
            max_concurrent_uni_streams: Arc::new(AtomicU32::new(DEFAULT_CONCURRENT_STREAMS)),
            max_concurrent_bi_streams: Arc::new(AtomicU32::new(DEFAULT_CONCURRENT_STREAMS)),
        };

        tokio::spawn(conn.clone().init(
            zero_rtt_accepted,
            heartbeat,
            handshake_timeout,
            gc_interval,
            gc_lifetime,
        ));

        conn
    }

    async fn init(
        self,
        zero_rtt_accepted: Option<ZeroRttAccepted>,
        heartbeat: Duration,
        handshake_timeout: Duration,
        gc_interval: Duration,
        gc_lifetime: Duration,
    ) {
        log::info!("connection established");

        tokio::spawn(self.clone().client_hello(zero_rtt_accepted));
        tokio::spawn(self.clone().timeout_handshake(handshake_timeout));
        tokio::spawn(self.clone().heartbeat(heartbeat));
        tokio::spawn(self.clone().collect_garbage(gc_interval, gc_lifetime));

        let err = loop {
            tokio::select! {
                res = self.accept_uni_stream() => match res {
                    Ok((recv, reg)) => tokio::spawn(self.clone().handle_uni_stream(recv, reg)),
                    Err(err) => break err,
                },
                res = self.accept_bi_stream() => match res {
                    Ok((stream, reg)) => tokio::spawn(self.clone().handle_bi_stream(stream, reg)),
                    Err(err) => break err,
                },
                res = self.accept_datagram() => match res {
                    Ok(dg) => tokio::spawn(self.clone().handle_datagram(dg)),
                    Err(err) => break err,
                },
            };
        };

        log::warn!("connection error: {err}");
    }

    async fn timeout_handshake(self, timeout: Duration) {
        time::sleep(timeout).await;

        if self.auth.get().is_none() {
            log::warn!("[authenticate] timeout");
            self.close();
        }
    }

    async fn handshake(&self, hello: &ServerHello) -> Result<(), Error> {
        if self.auth.get().is_some() {
            return Err(Error::DuplicatedHello);
        }

        match hello.handshake_code() {
            ServerHelloHeader::HANDSHAKE_CODE_SUCCESS => {
                self.auth.set(hello.port().unwrap());
                Ok(())
            }
            ServerHelloHeader::HANDSHAKE_CODE_AUTH_FAILED => Err(Error::AuthFailed),
            ServerHelloHeader::HANDSHAKE_CODE_BIND_FAILED => Err(Error::RemoteBindFailed),
            ServerHelloHeader::HANDSHAKE_CODE_PORT_DENIED => Err(Error::PortDenied),
            ServerHelloHeader::HANDSHAKE_CODE_NETWORK_DENIED => {
                Err(Error::NetworkDenied(self.network))
            }
            _ => unreachable!(),
        }
    }

    async fn collect_garbage(self, gc_interval: Duration, gc_lifetime: Duration) {
        loop {
            time::sleep(gc_interval).await;

            if self.is_closed() {
                break;
            }

            log::debug!("packet fragment garbage collecting event");
            self.model.collect_garbage(gc_lifetime);
        }
    }

    fn is_closed(&self) -> bool {
        self.inner.close_reason().is_some()
    }

    fn close(&self) {
        self.inner.close(ERROR_CODE, &[]);
    }
}

struct Endpoint {
    ep: QuinnEndpoint,
    server: ServerAddress,
    local: Address,
    uuid: Uuid,
    password: Arc<[u8]>,
    network: Network,
    udp_forward_mode: UdpForwardMode,
    udp_timeout: Duration,
    expected_port_range: RangeInclusive<u16>,
    zero_rtt_handshake: bool,
    heartbeat: Duration,
    handshake_timeout: Duration,
    task_negotiation_timeout: Duration,
    max_packet_size: usize,
    gc_interval: Duration,
    gc_lifetime: Duration,
    proxy_protocol: ProxyProtocol,
}

impl Endpoint {
    async fn connect(&mut self) -> Result<Connection, Error> {
        let mut last_err = None;

        for addr in self.server.resolve().await? {
            let connect_to = async {
                let match_ipv4 =
                    addr.is_ipv4() && self.ep.local_addr().map_or(false, |addr| addr.is_ipv4());
                let match_ipv6 =
                    addr.is_ipv6() && self.ep.local_addr().map_or(false, |addr| addr.is_ipv6());

                if !match_ipv4 && !match_ipv6 {
                    let bind_addr = if addr.is_ipv4() {
                        SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
                    } else {
                        SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
                    };

                    self.ep
                        .rebind(UdpSocket::bind(bind_addr).map_err(|err| {
                            Error::Socket("failed to create endpoint UDP socket", err)
                        })?)
                        .map_err(|err| {
                            Error::Socket("failed to rebind endpoint UDP socket", err)
                        })?;
                }

                let conn = self.ep.connect(addr, self.server.server_name())?;

                let (conn, zero_rtt_accepted) = if self.zero_rtt_handshake {
                    match conn.into_0rtt() {
                        Ok((conn, zero_rtt_accepted)) => (conn, Some(zero_rtt_accepted)),
                        Err(conn) => (conn.await?, None),
                    }
                } else {
                    (conn.await?, None)
                };

                Ok((conn, zero_rtt_accepted))
            };

            match connect_to.await {
                Ok((conn, zero_rtt_accepted)) => {
                    return Ok(Connection::new(
                        conn,
                        zero_rtt_accepted,
                        self.local.clone(),
                        self.uuid,
                        self.password.clone(),
                        self.network,
                        self.udp_forward_mode,
                        self.udp_timeout,
                        self.expected_port_range.clone(),
                        self.heartbeat,
                        self.handshake_timeout,
                        self.task_negotiation_timeout,
                        self.max_packet_size,
                        self.gc_interval,
                        self.gc_lifetime,
                        self.proxy_protocol,
                    ));
                }
                Err(err) => last_err = Some(err),
            }
        }

        Err(last_err.unwrap_or(Error::DnsResolve))
    }
}

#[derive(Debug)]
struct SkipServerVerification(Arc<CryptoProvider>);

impl SkipServerVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self(Arc::new(rustls::crypto::ring::default_provider())))
    }
}

impl danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<danger::ServerCertVerified, rustls::Error> {
        Ok(danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<danger::HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<danger::HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}
