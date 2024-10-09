use std::{
    collections::BTreeSet,
    fmt::{Display, Formatter, Result as FmtResult},
    fs::{self, File},
    io::BufReader,
    iter,
    net::IpAddr,
    ops::RangeInclusive,
    path::Path,
    str::FromStr,
};

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls_pemfile::Item;
#[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
use sysctl::CtlValue;
#[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd",
    target_os = "linux", target_os = "android"))]
use sysctl::Sysctl;

use asport::ForwardMode;

use crate::error::Error;

pub fn load_certs<P: AsRef<Path>>(path: P) -> Result<Vec<CertificateDer<'static>>, Error> {
    let mut file = BufReader::new(File::open(&path)
        .map_err(|e| Error::Io(e))?);
    let mut certs = Vec::new();

    while let Ok(Some(item)) = rustls_pemfile::read_one(&mut file) {
        if let Item::X509Certificate(cert) = item {
            certs.push(cert);
        }
    }

    // Der format
    if certs.is_empty() {
        certs = vec![CertificateDer::from(fs::read(&path)
            .map_err(|e| Error::Io(e))?)];
    }

    Ok(certs)
}

pub fn load_priv_key<P: AsRef<Path>>(path: P) -> Result<PrivateKeyDer<'static>, Error> {
    let mut file = BufReader::new(
        File::open(&path).map_err(|e| Error::Io(e))?
    );
    let mut priv_key: Option<PrivateKeyDer> = None;

    for item in iter::from_fn(|| rustls_pemfile::read_one(&mut file).transpose()) {
        match item {
            Ok(Item::Pkcs1Key(key)) => { priv_key = Some(PrivateKeyDer::from(key)) }
            Ok(Item::Pkcs8Key(key)) => { priv_key = Some(PrivateKeyDer::from(key)) }
            Ok(Item::Sec1Key(key)) => { priv_key = Some(PrivateKeyDer::from(key)) }
            _ => {}
        }
    }

    match priv_key {
        Some(key) => Ok(key),
        None => // Der format
            fs::read(&path).map(PrivateKeyDer::try_from).map_err(
                |e| Error::Io(e)
            )?.map_err(|e| Error::InvalidPrivateKey(e)),
    }
}
#[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
pub fn ephemeral_port_range() -> RangeInclusive<u16> {
    let first_ctl = sysctl::Ctl::new("net.inet.ip.portrange.first");
    let last_ctl = sysctl::Ctl::new("net.inet.ip.portrange.last");

    if let (Ok(first_ctl), Ok(last_ctl)) = (first_ctl, last_ctl) {
        // Actually, the first and last values should be u16, but sysctl crate returns them as i32.
        if let (Ok(CtlValue::Int(first)), Ok(CtlValue::Int(last))) = (first_ctl.value(), last_ctl.value()) {
            return (first as u16)..=(last as u16);
        }
    }

    // Default value for macOS, iOS and FreeBSD is 49152..=65535.
    49152..=65535
}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn ephemeral_port_range() -> RangeInclusive<u16> {
    let ctl = sysctl::Ctl::new("net.ipv4.ip_local_port_range");
    if let Ok(ctl) = ctl {
        if let Ok(value_str) = ctl.value_string() {
            let mut iter = value_str.split_whitespace();
            if let (Some(start), Some(end)) = (iter.next(), iter.next()) {
                if let (Ok(start), Ok(end)) = (start.parse::<u16>(), end.parse::<u16>()) {
                    return start..=end;
                }
            }
        }
    }

    // Default value for Linux is 32768..=60999.
    // See also: https://www.kernel.org/doc/html/latest//networking/ip-sysctl.html#ip-variables
    32768..=60999
}


#[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "freebsd",
    target_os = "linux", target_os = "android")))]
pub fn ephemeral_port_range() -> RangeInclusive<u16> {
    // The suggested range by RFC6335 and IANA.
    // See also: https://tools.ietf.org/html/rfc6335
    // https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml
    // Since Windows Vista/Server 2008 (6.0), the default dynamic port range is 49152..65535.
    // And earlier versions had been dropped from support.
    // See also: https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/default-dynamic-port-range-tcpip-chang
    // https://doc.rust-lang.org/stable/rustc/platform-support.html
    49152..=65535
}


pub enum CongestionControl {
    Cubic,
    NewReno,
    Bbr,
}

impl FromStr for CongestionControl {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
          match s.to_lowercase().as_str() {
            "cubic" => Ok(Self::Cubic),
            "new_reno" | "newreno" => Ok(Self::NewReno),
            "bbr" => Ok(Self::Bbr),
            _ => Err("invalid congestion control")
        }
    }
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum Network {
    Tcp,
    Udp,
    Both,
}

impl Network {
    pub(crate) fn is_tcp(&self) -> bool {
        matches!(self, Self::Tcp)
    }

    pub(crate) fn is_udp(&self) -> bool {
        matches!(self, Self::Udp)
    }

    pub(crate) fn is_both(&self) -> bool {
        matches!(self, Self::Both)
    }

    pub(crate) fn tcp(&self) -> bool {
        self.is_both() || self.is_tcp()
    }

    pub(crate) fn udp(&self) -> bool {
        self.is_both() || self.is_udp()
    }
}

impl FromStr for Network {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
       match s.to_lowercase().as_str() {
            "tcp" => Ok(Self::Tcp),
            "udp" => Ok(Self::Udp),
            "both" | "tcpudp" | "tcp_udp" | "tcp-udp" | "all" => Ok(Self::Both),
            _ => Err("invalid network")
        }
    }
}

impl Display for Network {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            Self::Tcp => write!(f, "tcp"),
            Self::Udp => write!(f, "udp"),
            Self::Both => write!(f, "both"),
        }
    }
}

pub fn merge_network(allow_network: Network, expected_network: Network) -> Result<Network, Error> {
    match (allow_network, expected_network) {
        (Network::Both, _) => Ok(expected_network),
        (Network::Tcp, Network::Tcp) => Ok(Network::Tcp),
        (Network::Udp, Network::Udp) => Ok(Network::Udp),
        _ => Err(Error::NetworkDenied(expected_network)),
    }
}

#[derive(Clone, Copy)]
pub enum UdpForwardMode {
    Native,
    Quic,
}

impl Display for UdpForwardMode {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            Self::Native => write!(f, "native"),
            Self::Quic => write!(f, "quic"),
        }
    }
}

pub struct NetworkUdpForwardModeCombine(Network, UdpForwardMode);

impl NetworkUdpForwardModeCombine {
    pub fn new(network: Network, mode: UdpForwardMode) -> Self {
        Self(network, mode)
    }
}

impl From<ForwardMode> for NetworkUdpForwardModeCombine {
    fn from(mode: ForwardMode) -> Self {
        match mode {
            ForwardMode::Tcp => Self::new(Network::Tcp, UdpForwardMode::Native),
            ForwardMode::UdpNative => Self::new(Network::Udp, UdpForwardMode::Native),
            ForwardMode::UdpQuic => Self::new(Network::Udp, UdpForwardMode::Quic),
            ForwardMode::TcpUdpNative => Self::new(Network::Both, UdpForwardMode::Native),
            ForwardMode::TcpUdpQuic => Self::new(Network::Both, UdpForwardMode::Quic),
        }
    }
}

impl From<NetworkUdpForwardModeCombine> for (Network, UdpForwardMode) {
    fn from(value: NetworkUdpForwardModeCombine) -> Self {
        (value.0, value.1)
    }
}

pub struct User {
    password: Box<[u8]>,
    bind_ip: IpAddr,
    only_v6: Option<bool>,
    allow_ports: BTreeSet<u16>,
    allow_network: Network,
}

impl User {
    pub fn new(password: Box<[u8]>,
               bind_ip: IpAddr,
               allow_ports: BTreeSet<u16>,
               only_v6: Option<bool>,
               allow_network: Network) -> Self {
        Self {
            password,
            bind_ip,
            only_v6,
            allow_ports,
            allow_network,
        }
    }

    pub fn password(&self) -> &[u8] {
        &self.password
    }

    pub fn listen_ip(&self) -> IpAddr {
        self.bind_ip
    }

    pub fn allow_ports(&self) -> BTreeSet<u16> {
        self.allow_ports.clone()
    }

    pub fn only_v6(&self) -> Option<bool> {
        self.only_v6
    }

    pub fn allow_network(&self) -> &Network {
        &self.allow_network
    }
}