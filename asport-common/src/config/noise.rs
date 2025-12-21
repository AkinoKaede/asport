use std::sync::Arc;

use serde::Deserialize;

use super::serde::deserialize_from_base64_opt;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityNoiseConfig {
    #[serde(default = "pattern")]
    pub pattern: String,
    #[serde(default, deserialize_with = "deserialize_from_base64_opt")]
    pub local_private_key: Option<Arc<[u8]>>,
    #[serde(default, deserialize_with = "deserialize_from_base64_opt")]
    pub remote_public_key: Option<Arc<[u8]>>,
}

pub fn pattern() -> String {
    DEFAULT_PATTERN.to_string()
}

const DEFAULT_PATTERN: &str = "Noise_NK_25519_ChaChaPoly_BLAKE2s";
