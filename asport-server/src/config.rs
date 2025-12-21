use asport_common::config::{
    serde::{deserialize_alpn, deserialize_duration, deserialize_from_str},
    SecurityNoiseConfig,
};
use log::LevelFilter;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde::{de::Error as DeError, Deserialize, Deserializer};
use std::{
    collections::{BTreeSet, HashMap},
    net::{IpAddr, SocketAddr},
    ops::{BitOr, RangeInclusive},
    path::PathBuf,
    sync::OnceLock,
    time::Duration,
};
use uuid::Uuid;

use crate::utils::{
    load_certs, load_priv_key, parse_pem_certs, parse_pem_priv_key, CongestionControl, Network,
    SecurityType,
};

// TODO: need a better way to do this
static CONFIG_BASE_PATH: OnceLock<PathBuf> = OnceLock::new();

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub server: SocketAddr,

    pub proxies: Vec<ProxyConfig>,

    pub security: SecurityConfig,

    #[serde(
        default = "default::congestion_control",
        deserialize_with = "deserialize_from_str"
    )]
    pub congestion_control: CongestionControl,

    pub only_v6: Option<bool>,

    #[serde(
        default = "default::handshake_timeout",
        deserialize_with = "deserialize_duration"
    )]
    pub handshake_timeout: Duration,

    #[serde(default = "default::authentication_failed_reply")]
    pub authentication_failed_reply: bool,

    #[serde(
        default = "default::task_negotiation_timeout",
        deserialize_with = "deserialize_duration"
    )]
    pub task_negotiation_timeout: Duration,

    #[serde(
        default = "default::max_idle_time",
        deserialize_with = "deserialize_duration"
    )]
    pub max_idle_time: Duration,

    #[serde(default = "default::max_packet_size")]
    pub max_packet_size: usize,

    #[serde(default = "default::send_window")]
    pub send_window: u64,

    #[serde(default = "default::receive_window")]
    pub receive_window: u32,

    #[serde(
        default = "default::log_level",
        deserialize_with = "deserialize_from_str"
    )]
    pub log_level: LevelFilter,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyConfig {
    #[serde(deserialize_with = "deserialize_users")]
    pub users: HashMap<Uuid, Box<[u8]>>,

    #[serde(default = "default::proxy::bind_ip")]
    pub bind_ip: IpAddr,

    #[serde(
        default = "default::proxy::allow_ports",
        deserialize_with = "deserialize_ports"
    )]
    pub allow_ports: BTreeSet<u16>,

    pub only_v6: Option<bool>,

    #[serde(
        default = "default::proxy::network",
        deserialize_with = "deserialize_network"
    )]
    pub allow_network: Network,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityConfig {
    #[serde(
        default = "default::security::default",
        deserialize_with = "deserialize_from_str",
        alias = "type"
    )]
    pub type_: SecurityType,

    #[serde(default = "default::security::zero_rtt_handshake")]
    pub zero_rtt_handshake: bool,

    pub tls: Option<SecurityTlsConfig>,

    pub noise: Option<SecurityNoiseConfig>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityTlsConfig {
    #[serde(deserialize_with = "deserialize_certs")]
    pub certificate: Vec<CertificateDer<'static>>,

    #[serde(deserialize_with = "deserialize_priv_key")]
    pub private_key: PrivateKeyDer<'static>,

    #[serde(
        default = "default::security::tls::alpn",
        deserialize_with = "deserialize_alpn"
    )]
    pub alpn: Vec<Vec<u8>>,
}

impl Config {
    pub fn build(path: PathBuf) -> Result<Self, config::ConfigError> {
        let base_path = path.parent();
        match base_path {
            Some(base_path) => {
                CONFIG_BASE_PATH.set(base_path.to_path_buf()).map_err(|e| {
                    config::ConfigError::custom(format!("failed to set config path: {:?}", e))
                })?;
            }
            None => {
                return Err(config::ConfigError::custom("config path is not a file"));
            }
        }

        let cfg = config::Config::builder()
            .add_source(config::File::from(path))
            .build()?;

        cfg.try_deserialize::<Config>()
    }
}

mod default {
    use std::time::Duration;

    use log::LevelFilter;

    use crate::utils::CongestionControl;

    pub fn congestion_control() -> CongestionControl {
        CongestionControl::Cubic
    }

    pub fn handshake_timeout() -> Duration {
        Duration::from_secs(3)
    }

    pub fn authentication_failed_reply() -> bool {
        true
    }

    pub fn task_negotiation_timeout() -> Duration {
        Duration::from_secs(3)
    }

    pub fn max_idle_time() -> Duration {
        Duration::from_secs(10)
    }

    pub fn max_packet_size() -> usize {
        1350
    }

    pub fn send_window() -> u64 {
        8 * 1024 * 1024 * 2
    }

    pub fn receive_window() -> u32 {
        8 * 1024 * 1024
    }

    pub fn log_level() -> LevelFilter {
        LevelFilter::Warn
    }

    pub mod proxy {
        use std::collections::BTreeSet;
        use std::net::{IpAddr, Ipv6Addr};

        use crate::utils::{ephemeral_port_range, Network};

        pub fn bind_ip() -> IpAddr {
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        }

        pub fn allow_ports() -> BTreeSet<u16> {
            ephemeral_port_range().collect()
        }

        pub fn network() -> Network {
            Network::TCP | Network::UDP
        }
    }

    pub mod security {
        use crate::utils::SecurityType;

        pub fn default() -> SecurityType {
            SecurityType::Tls
        }

        pub fn zero_rtt_handshake() -> bool {
            false
        }

        pub mod tls {
            pub fn alpn() -> Vec<Vec<u8>> {
                vec![b"asport".to_vec()]
            }
        }

    }
}

pub fn deserialize_users<'de, D>(deserializer: D) -> Result<HashMap<Uuid, Box<[u8]>>, D::Error>
where
    D: Deserializer<'de>,
{
    let users = HashMap::<Uuid, String>::deserialize(deserializer)?;

    if users.is_empty() {
        return Err(DeError::custom("users cannot be empty"));
    }

    Ok(users
        .into_iter()
        .map(|(k, v)| (k, v.into_bytes().into_boxed_slice()))
        .collect())
}

pub fn deserialize_ports<'de, D>(deserializer: D) -> Result<BTreeSet<u16>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum PortRange {
        Range(RangeInclusive<u16>),
        Single(u16),
    }

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum PortRanges {
        Array(Vec<PortRange>),
        Range(RangeInclusive<u16>),
        Single(u16),
    }

    let ranges = PortRanges::deserialize(deserializer)?;

    let mut set = BTreeSet::<u16>::new();

    match ranges {
        PortRanges::Array(array) => {
            for range in array {
                match range {
                    PortRange::Range(range) => {
                        set.extend(range);
                    }
                    PortRange::Single(port) => {
                        set.insert(port);
                    }
                }
            }
        }
        PortRanges::Range(range) => {
            set.extend(range);
        }
        PortRanges::Single(port) => {
            set.insert(port);
        }
    }

    Ok(set)
}

pub fn deserialize_network<'de, D>(deserializer: D) -> Result<Network, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Middle {
        #[serde(deserialize_with = "deserialize_from_str")]
        Single(Network),

        Double(
            #[serde(deserialize_with = "deserialize_from_str")] Network,
            #[serde(deserialize_with = "deserialize_from_str")] Network,
        ),
    }

    let middle = Middle::deserialize(deserializer)?;
    match middle {
        Middle::Single(network) => Ok(network),
        Middle::Double(a, b) => Ok(a.bitor(b)),
    }
}

pub fn deserialize_certs<'de, D>(deserializer: D) -> Result<Vec<CertificateDer<'static>>, D::Error>
where
    D: Deserializer<'de>,
{
    let str = String::deserialize(deserializer)?;

    if str.contains("-----BEGIN CERTIFICATE-----") {
        return parse_pem_certs(str.into_bytes()).map_err(DeError::custom);
    }

    let path = PathBuf::from(str);
    let path = CONFIG_BASE_PATH.get().unwrap().join(path);

    load_certs(path).map_err(DeError::custom)
}

pub fn deserialize_priv_key<'de, D>(deserializer: D) -> Result<PrivateKeyDer<'static>, D::Error>
where
    D: Deserializer<'de>,
{
    let str = String::deserialize(deserializer)?;
    if str.contains("-----BEGIN PRIVATE KEY-----")
        || str.contains("-----BEGIN RSA PRIVATE KEY-----")
        || str.contains("-----BEGIN EC PRIVATE KEY-----")
    {
        return parse_pem_priv_key(str.into_bytes()).map_err(DeError::custom);
    }

    let path = PathBuf::from(str);
    let path = CONFIG_BASE_PATH.get().unwrap().join(path);

    load_priv_key(path).map_err(DeError::custom)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_ports() {
        let s = r#"1"#;
        let ports: BTreeSet<u16> =
            deserialize_ports(&mut serde_json::Deserializer::from_str(s)).unwrap();
        assert_eq!(ports, vec![1].into_iter().collect());

        let s = r#"{"start": 1, "end": 5}"#;
        let ports: BTreeSet<u16> =
            deserialize_ports(&mut serde_json::Deserializer::from_str(s)).unwrap();
        assert_eq!(ports, vec![1, 2, 3, 4, 5].into_iter().collect());

        let s = r#"[1, 2, 3]"#;
        let ports: BTreeSet<u16> =
            deserialize_ports(&mut serde_json::Deserializer::from_str(s)).unwrap();
        assert_eq!(ports, vec![1, 2, 3].into_iter().collect());

        let s = r#"[{"start": 1, "end": 5}, 8, {"start": 2, "end": 3}]"#;
        let ports: BTreeSet<u16> =
            deserialize_ports(&mut serde_json::Deserializer::from_str(s)).unwrap();
        assert_eq!(ports, vec![1, 2, 3, 4, 5, 8].into_iter().collect());

        let s = r#"[]"#;
        let ports: BTreeSet<u16> =
            deserialize_ports(&mut serde_json::Deserializer::from_str(s)).unwrap();
        assert_eq!(ports, vec![].into_iter().collect());
    }

    #[test]
    fn test_deserialize_network() {
        let s = r#""tcp""#;
        let network: Network =
            deserialize_network(&mut serde_json::Deserializer::from_str(s)).unwrap();
        assert_eq!(network, Network::TCP);

        let s = r#""udp""#;
        let network: Network =
            deserialize_network(&mut serde_json::Deserializer::from_str(s)).unwrap();
        assert_eq!(network, Network::UDP);

        let s = r#""tcpudp""#;
        let network: Network =
            deserialize_network(&mut serde_json::Deserializer::from_str(s)).unwrap();
        assert_eq!(network, Network::TCP | Network::UDP);

        let s = r#""tcp_udp""#;
        let network: Network =
            deserialize_network(&mut serde_json::Deserializer::from_str(s)).unwrap();
        assert_eq!(network, Network::TCP | Network::UDP);

        let s = r#""tcp-udp""#;
        let network: Network =
            deserialize_network(&mut serde_json::Deserializer::from_str(s)).unwrap();
        assert_eq!(network, Network::TCP | Network::UDP);

        let s = r#""all""#;
        let network: Network =
            deserialize_network(&mut serde_json::Deserializer::from_str(s)).unwrap();
        assert_eq!(network, Network::TCP | Network::UDP);

        let s = r#"["tcp", "tcp"]"#;
        let network: Network =
            deserialize_network(&mut serde_json::Deserializer::from_str(s)).unwrap();
        assert_eq!(network, Network::TCP);

        let s = r#"["tcp", "all"]"#;
        let network: Network =
            deserialize_network(&mut serde_json::Deserializer::from_str(s)).unwrap();
        assert_eq!(network, Network::TCP | Network::UDP);

        let s = r#"["tcp", "udp"]"#;
        let network: Network =
            deserialize_network(&mut serde_json::Deserializer::from_str(s)).unwrap();
        assert_eq!(network, Network::TCP | Network::UDP);
    }
}
