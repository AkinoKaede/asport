use std::{
    fmt::Display,
    ops::RangeInclusive,
    path::PathBuf,
    str::FromStr,
    sync::{Arc, OnceLock},
    time::Duration,
};

use humantime::Duration as HumanDuration;
use log::LevelFilter;
use rustls::RootCertStore;
use serde::{de::Error as DeError, Deserialize, Deserializer};
use uuid::Uuid;

use crate::utils::{Address, CongestionControl, load_certs, Network, ProxyProtocol, UdpForwardMode};

// TODO: need a better way to do this
static CONFIG_BASE_PATH: OnceLock<PathBuf> = OnceLock::new();

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub server: Address,

    pub local: Address,

    pub uuid: Uuid,

    #[serde(deserialize_with = "deserialize_password")]
    pub password: Arc<[u8]>,

    #[serde(
        default = "default::network",
        deserialize_with = "deserialize_from_str"
    )]
    pub network: Network,

    #[serde(
        default = "default::udp_forward_mode",
        deserialize_with = "deserialize_from_str"
    )]
    pub udp_forward_mode: UdpForwardMode,

    #[serde(
        default = "default::udp_timeout",
        deserialize_with = "deserialize_duration"
    )]
    pub udp_timeout: Duration,

    #[serde(
        alias = "port",
        default = "default::expected_port_range",
        deserialize_with = "deserialize_expected_port_range"
    )]
    pub expected_port_range: RangeInclusive<u16>,

    #[serde(alias = "sni")]
    pub server_name: Option<String>,

    #[serde(
        default = "default::certificates::default",
        deserialize_with = "deserialize_certificates"
    )]
    pub certificates: RootCertStore,

    #[serde(default = "default::disable_sni")]
    pub disable_sni: bool,

    #[serde(
        default = "default::congestion_control",
        deserialize_with = "deserialize_from_str"
    )]
    pub congestion_control: CongestionControl,

    #[serde(
        default = "default::alpn",
        deserialize_with = "deserialize_alpn"
    )]
    pub alpn: Vec<Vec<u8>>,

    #[serde(default = "default::zero_rtt_handshake")]
    pub zero_rtt_handshake: bool,

    #[serde(
        default = "default::healthy_check",
        deserialize_with = "deserialize_duration"
    )]
    pub healthy_check: Duration,

    #[serde(
        default = "default::timeout",
        deserialize_with = "deserialize_duration"
    )]
    pub timeout: Duration,

    #[serde(
        default = "default::handshake_timeout",
        deserialize_with = "deserialize_duration"
    )]
    pub handshake_timeout: Duration,

    #[serde(
        default = "default::task_negotiation_timeout",
        deserialize_with = "deserialize_duration"
    )]
    pub task_negotiation_timeout: Duration,

    #[serde(
        default = "default::heartbeat",
        deserialize_with = "deserialize_duration"
    )]
    pub heartbeat: Duration,

    #[serde(default = "default::max_packet_size")]
    pub max_packet_size: usize,

    #[serde(default = "default::send_window")]
    pub send_window: u64,

    #[serde(default = "default::receive_window")]
    pub receive_window: u32,

    #[serde(
        default = "default::gc_interval",
        deserialize_with = "deserialize_duration"
    )]
    pub gc_interval: Duration,

    #[serde(
        default = "default::gc_lifetime",
        deserialize_with = "deserialize_duration"
    )]
    pub gc_lifetime: Duration,

    #[serde(
        default = "default::proxy_protocol",
        deserialize_with = "deserialize_from_str"
    )]
    pub proxy_protocol: ProxyProtocol,

    #[serde(default = "default::log_level")]
    pub log_level: LevelFilter,
}

impl Config {
    pub fn build(path: PathBuf) -> Result<Self, config::ConfigError> {
        let base_path = path.parent();
        match base_path {
            Some(base_path) => {
                CONFIG_BASE_PATH.set(base_path.to_path_buf()).map_err(
                    |e| config::ConfigError::custom(
                        format!("failed to set config path: {:?}", e)
                    )
                )?;
            }
            None => {
                return Err(config::ConfigError::custom("config path is not a file"));
            }
        }

        let cfg = config::Config::builder()
            .add_source(config::File::from(path))
            .build()?;

        match cfg.try_deserialize::<Config>() {
            Ok(cfg) => {
                Ok(cfg)
            }
            Err(err) => Err(config::ConfigError::custom(err)),
        }
    }
}

mod default {
    use std::ops::RangeInclusive;
    use std::time::Duration;

    use log::LevelFilter;

    use crate::utils::{CongestionControl, Network, ProxyProtocol, UdpForwardMode};

    pub mod certificates {
        use std::path::PathBuf;

        use rustls::RootCertStore;

        use crate::utils::load_certs;

        pub fn paths() -> Vec<PathBuf> {
            Vec::new()
        }

        pub fn disable_native() -> bool {
            false
        }

        pub fn default() -> RootCertStore {
            let paths: Vec<PathBuf> = Vec::new();
            match load_certs(paths, false) {
                Ok(certs) => certs,
                Err(err) => {
                    log::error!("failed to load certificates: {}", err);
                    std::process::exit(1);
                }
            }
        }
    }

    pub fn network() -> Network {
        Network::Both
    }

    pub fn udp_forward_mode() -> UdpForwardMode {
        UdpForwardMode::Native
    }

    pub fn udp_timeout() -> Duration {
        Duration::from_secs(60)
    }

    pub fn expected_port_range() -> RangeInclusive<u16> {
        1..=65535
    }

    pub fn disable_sni() -> bool {
        false
    }

    pub fn congestion_control() -> CongestionControl {
        CongestionControl::Cubic
    }

    pub fn alpn() -> Vec<Vec<u8>> {
        vec![b"asport".to_vec()]
    }

    pub fn zero_rtt_handshake() -> bool {
        false
    }

    pub fn healthy_check() -> Duration {
        Duration::from_secs(20)
    }

    pub fn timeout() -> Duration {
        Duration::from_secs(8)
    }

    pub fn handshake_timeout() -> Duration {
        Duration::from_secs(3)
    }

    pub fn task_negotiation_timeout() -> Duration {
        Duration::from_secs(3)
    }

    pub fn heartbeat() -> Duration {
        Duration::from_secs(3)
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

    pub fn gc_interval() -> Duration {
        Duration::from_secs(3)
    }

    pub fn gc_lifetime() -> Duration {
        Duration::from_secs(15)
    }

    pub fn proxy_protocol() -> ProxyProtocol {
        ProxyProtocol::None
    }

    pub fn log_level() -> LevelFilter {
        LevelFilter::Warn
    }
}

pub fn deserialize_from_str<'de, T, D>(deserializer: D) -> Result<T, D::Error>
where
    T: FromStr,
    <T as FromStr>::Err: Display,
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    T::from_str(&s).map_err(DeError::custom)
}

pub fn deserialize_password<'de, D>(deserializer: D) -> Result<Arc<[u8]>, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    Ok(Arc::from(s.into_bytes().into_boxed_slice()))
}

pub fn deserialize_alpn<'de, D>(deserializer: D) -> Result<Vec<Vec<u8>>, D::Error>
where
    D: Deserializer<'de>,
{
    let s = Vec::<String>::deserialize(deserializer)?;
    Ok(s.into_iter().map(|alpn| alpn.into_bytes()).collect())
}

pub fn deserialize_duration<'de, D>(deserializer: D) -> Result<Duration, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;

    s.parse::<HumanDuration>()
        .map(|d| *d)
        .map_err(DeError::custom)
}

pub fn deserialize_expected_port_range<'de, D>(deserializer: D) -> Result<RangeInclusive<u16>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum PortRange {
        Single(u16),
        Range(u16, u16),
        RangeInclusive(RangeInclusive<u16>),
    }

    let range = PortRange::deserialize(deserializer)?;

    match range {
        PortRange::Single(port) => Ok(port..=port),
        PortRange::Range(start, end) => Ok(start..=end),
        PortRange::RangeInclusive(range) => Ok(range),
    }
}

pub fn deserialize_certificates<'de, D>(deserializer: D) -> Result<RootCertStore, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Certificates {
        #[serde(default = "default::certificates::paths")]
        paths: Vec<PathBuf>,
        #[serde(default = "default::certificates::disable_native")]
        disable_native: bool,
    }

    let certs_cfg = Certificates::deserialize(deserializer)?;

    let base_path = CONFIG_BASE_PATH.get().unwrap();

    let paths = certs_cfg.paths.iter().map(|path| base_path.join(path)).collect();

    match load_certs(paths, certs_cfg.disable_native) {
        Ok(certs) => Ok(certs),
        Err(err) => Err(DeError::custom(err)),
    }
}