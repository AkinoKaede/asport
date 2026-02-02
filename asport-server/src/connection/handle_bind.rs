use std::{
    collections::BTreeSet,
    net::{IpAddr, SocketAddr},
    sync::LazyLock,
};

use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::{
    io::Result as IoResult,
    net::{TcpListener, UdpSocket},
};

use crate::{
    error::Error,
    utils::{ephemeral_port_range, Network},
};

use super::{udp_sessions::UdpSessions, Connection};

static EPHEMERAL_PORTS: LazyLock<BTreeSet<u16>> = LazyLock::new(|| ephemeral_port_range().collect());

impl Connection {
    async fn bind_tcp(
        &self,
        bind_ip: IpAddr,
        port: u16,
        only_v6: Option<bool>,
    ) -> IoResult<TcpListener> {
        let domain = match bind_ip {
            IpAddr::V4(_) => Domain::IPV4,
            IpAddr::V6(_) => Domain::IPV6,
        };

        let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;

        if let Some(only_v6) = only_v6 {
            socket.set_only_v6(only_v6)?;
        }

        socket.set_nonblocking(true)?;

        socket.bind(&SockAddr::from(SocketAddr::new(bind_ip, port)))?;

        // backlog is the queue length for pending connections
        socket.listen(128)?;

        TcpListener::from_std(socket.into())
    }

    async fn bind_udp(
        &self,
        bind_ip: IpAddr,
        port: u16,
        only_v6: Option<bool>,
    ) -> IoResult<UdpSocket> {
        let domain = match bind_ip {
            IpAddr::V4(_) => Domain::IPV4,
            IpAddr::V6(_) => Domain::IPV6,
        };

        let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;

        if let Some(only_v6) = only_v6 {
            socket.set_only_v6(only_v6)?;
        }

        socket.set_nonblocking(true)?;

        socket.bind(&SockAddr::from(SocketAddr::new(bind_ip, port)))?;

        UdpSocket::from_std(socket.into())
    }

    pub(crate) async fn bind(
        &self,
        bind_ip: IpAddr,
        bind_ports: BTreeSet<u16>,
        only_v6: Option<bool>,
        network: &Network,
    ) -> Result<u16, Error> {
        let ports = {
            if network.both_enabled() {
                bind_ports.into_iter().collect()
            } else {
                match bind_ports == *EPHEMERAL_PORTS {
                    // workaround for ephemeral ports, make it chosen by OS.
                    true => vec![0],
                    false => bind_ports.into_iter().collect(),
                }
            }
        };

        // NOTICE: const_btree_len is still unstable, so we have to use this workaround.
        if ports.is_empty() {
            return Err(Error::PortDenied);
        }

        for port in ports {
            let tcp_listener = async {
                if network.tcp_enabled() {
                    return Some(self.bind_tcp(bind_ip, port, only_v6).await);
                }

                None
            }
            .await;

            let udp_socket = async {
                if network.udp_enabled() {
                    return Some(self.bind_udp(bind_ip, port, only_v6).await);
                }

                None
            }
            .await;

            match (tcp_listener, udp_socket) {
                (Some(Ok(tcp_listener)), Some(Ok(udp_socket))) => {
                    self.clone().handle_tcp_listener(tcp_listener).await;
                    let mut udp_sessions = self.udp_sessions.lock().await;
                    *udp_sessions = Some(UdpSessions::with_timeout(
                        self.clone(),
                        udp_socket,
                        self.max_packet_size,
                        self.udp_session_timeout,
                    ));

                    return Ok(port);
                }

                (Some(Ok(tcp_listener)), None) => {
                    let port = tcp_listener.local_addr().unwrap().port(); // Get actual port when port is 0
                    self.clone().handle_tcp_listener(tcp_listener).await;
                    return Ok(port);
                }

                (None, Some(Ok(udp_socket))) => {
                    let port = udp_socket.local_addr().unwrap().port(); // Get actual port when port is 0
                    let mut udp_sessions = self.udp_sessions.lock().await;
                    *udp_sessions = Some(UdpSessions::with_timeout(
                        self.clone(),
                        udp_socket,
                        self.max_packet_size,
                        self.udp_session_timeout,
                    ));

                    return Ok(port);
                }

                _ => {}
            }
        }

        Err(Error::BindFailed)
    }
}
