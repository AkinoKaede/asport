use std::{any::Any, sync::Arc};

use hyphae_handshake::{crypto::{InitialCrypto, SymmetricKey, SyncCryptoBackend, TransportCrypto, TransportRekey, HYPHAE_AEAD_TAG_LEN}, customization::SyncHandshakeConfig, handshake::{AllocHyphaeHandshake, HandshakeVersion}, quic::{to_tls_error_code, QUIC_V1_TRANSPORT_LABEL}, Error};
use quinn_proto::{crypto, transport_parameters::TransportParameters, ConnectionId, Side};

use crate::{sessionkeys::{initial_keys, keys_from_level_secret, packet_keys_from_level_secret}, util::HandshakeMessageFramer, config::HyphaeCryptoConfig, customization::QuinnHandshakeData};

pub struct HyphaeSession<T, B>
where
    T: SyncHandshakeConfig,
    T::Driver: QuinnHandshakeData,
    B: SyncCryptoBackend,
{
    pub(crate) config: Arc<HyphaeCryptoConfig<T, B>>,
    pub(crate) handshake_data_ready: bool,
    pub(crate) failed: bool,
    pub(crate) initiator: bool,
    pub(crate) handshake: Option<AllocHyphaeHandshake<T::Driver, B, Arc<B>>>,
    pub(crate) rekey: Option<(B::TransportRekey, B::TransportCrypto)>,
    pub(crate) framer: HandshakeMessageFramer,
    pub(crate) params: Option<Vec<u8>>,
    pub(crate) peer_params: Option<TransportParameters>,
    pub(crate) server_name: Option<String>,
}

impl <T, B> HyphaeSession<T, B>
where
    T: SyncHandshakeConfig,
    T::Driver: QuinnHandshakeData,
    B: SyncCryptoBackend,
{
    fn read_handshake_inner(&mut self, buf: &[u8]) -> Result<bool, Error> {
        self.framer.injest_bytes(buf).map_err(handshake_failed)?;

        let mut new_handshake_data = false;

        while let Some(message) = self.framer.next() {
            let handshake = match self.handshake.as_mut() {
                Some(handshake) => {
                    handshake.read_message(message)?;
                    handshake
                },
                None => {
                    if self.initiator {
                        unreachable!();
                    }
                    self.handshake.insert(
                        AllocHyphaeHandshake::new_responder(
                            &self.config.handshake_config,
                            self.config.crypto.clone(),
                            HandshakeVersion::Version1,
                            QUIC_V1_TRANSPORT_LABEL,
                            self.params.take().unwrap_or_default(),
                            message
                        )?
                    )
                },
            };
            
            if self.peer_params.is_none() {
                if let Some(mut peer_params_bytes) = handshake.peer_params() {
                    self.peer_params = Some(TransportParameters::read(Side::Client, &mut peer_params_bytes).map_err(handshake_failed)?);
                }
            }

            if !self.handshake_data_ready && (handshake.handshake_driver().handshake_data().is_some() || handshake.is_handshake_finished()) {
                self.handshake_data_ready = true;
                new_handshake_data = true;
            }
        }

        Ok(new_handshake_data)
    }

    fn write_handshake_inner(&mut self, buf: &mut Vec<u8>) -> Result<Option<crypto::Keys>, Error> {
        let handshake = match self.handshake.as_mut() {
            Some(h) => h,
            None => {
                if !self.initiator {
                    unreachable!();
                }
                self.handshake.insert(
                    AllocHyphaeHandshake::new_initiator(
                        &self.config.handshake_config,
                        self.config.crypto.clone(),
                        HandshakeVersion::Version1,
                        QUIC_V1_TRANSPORT_LABEL,
                        self.params.take().unwrap_or_default(),
                        self.server_name.take().unwrap_or_default().as_str()
                    )?
                )
            },
        };

        if handshake.next_level_secret_ready() {
            let mut level_secret = SymmetricKey::default();
            handshake.next_level_secret(&mut level_secret)?;
            let keys = keys_from_level_secret(handshake.is_initiator(), &level_secret, &handshake.transport_crypto()?);

            if self.rekey.is_none() && handshake.is_handshake_finished() {
                let transport_crypto = handshake.transport_crypto()?;
                let rekey = self.rekey.insert((Default::default(), transport_crypto));
                handshake.export_1rtt_rekey(&mut rekey.0)?;
            }

            return Ok(Some(keys));
        }

        let mut message = Vec::new();
        handshake.write_message(&mut message)?;
        if !message.is_empty() {
            HandshakeMessageFramer::write_frame(buf, &message).map_err(handshake_failed)?;
        }

        Ok(None)
    }
}

impl <T, B> crypto::Session for HyphaeSession<T, B>
where
    T: SyncHandshakeConfig,
    T::Driver: QuinnHandshakeData,
    B: SyncCryptoBackend,
{
    fn initial_keys(&self, dst_cid: &quinn_proto::ConnectionId, side: quinn_proto::Side) -> crypto::Keys {
        let local_is_initiator = match side {
            Side::Client => true,
            Side::Server => false,
        };
        initial_keys(local_is_initiator, HandshakeVersion::Version1, QUIC_V1_TRANSPORT_LABEL, &dst_cid, &self.config.crypto.initial_crypto())
    }

    fn handshake_data(&self) -> Option<Box<dyn Any>> {
        let driver = self.handshake.as_ref()?.handshake_driver();
        match driver.handshake_data() {
            Some(hd) => Some(Box::new(hd)),
            None => None,
        }
    }

    fn peer_identity(&self) -> Option<Box<dyn Any>> {
        let handshake = self.handshake.as_ref()?;
        let driver = handshake.handshake_driver();
        let remote_public = handshake.remote_public();
        let final_handshake_hash = handshake.final_handshake_hash();

        match driver.peer_identity(remote_public, final_handshake_hash) {
            Some(pi) => Some(Box::new(pi)),
            None => None,
        }
    }

    fn early_crypto(&self) -> Option<(Box<dyn crypto::HeaderKey>, Box<dyn crypto::PacketKey>)> {
        None
    }

    fn early_data_accepted(&self) -> Option<bool> {
        None
    }

    fn is_handshaking(&self) -> bool {
        match self.handshake.as_ref() {
            Some(handshake) => !handshake.is_handshake_finished(),
            None => true,
        }
    }

    fn read_handshake(&mut self, buf: &[u8]) -> Result<bool, quinn_proto::TransportError> {
        if self.failed {
            return Err(quinn_proto::TransportErrorCode::crypto(to_tls_error_code(Error::Internal)).into());
        }
        
        self.read_handshake_inner(buf).map_err(|err| {
            self.failed = true;
            self.handshake = None;

            quinn_proto::TransportErrorCode::crypto(to_tls_error_code(err)).into()
        })
    }

    fn transport_parameters(&self) -> Result<Option<quinn_proto::transport_parameters::TransportParameters>, quinn_proto::TransportError> {
        Ok(self.peer_params)
    }

    fn write_handshake(&mut self, buf: &mut Vec<u8>) -> Option<crypto::Keys> {
        if self.failed {
            return None;
        }

        match self.write_handshake_inner(buf) {
            Ok(keys) => keys,
            Err(_) => {
                self.failed = true;
                self.handshake = None;

                // Quinn doesn't have a way to signal an error on crypto writes,
                // send a `Failed` message instead to fail the handshake quickly
                // instead of letting it time out.
                buf.clear();
                buf.push(255);
                None
            },
        }
    }

    fn next_1rtt_keys(&mut self) -> Option<crypto::KeyPair<Box<dyn crypto::PacketKey>>> {
        match self.rekey.as_mut() {
            Some((rekey, transport_crypto)) => {
                let mut next_1rtt_secret = SymmetricKey::default();
                rekey.next_1rtt_secret(&mut next_1rtt_secret);
                let packet_keys = packet_keys_from_level_secret(self.initiator, &next_1rtt_secret, transport_crypto);
                Some(packet_keys)
            },
            None => None,
        }
    }

    fn is_valid_retry(&self, orig_dst_cid: &ConnectionId, header: &[u8], payload: &[u8]) -> bool {
        if payload.len() < HYPHAE_AEAD_TAG_LEN {
            return false;
        }

        let initial_crypto = self.config.crypto.initial_crypto();
        let mut retry_key = SymmetricKey::default();
        initial_crypto.retry_tag_secret(HandshakeVersion::Version1, QUIC_V1_TRANSPORT_LABEL, &orig_dst_cid, &mut retry_key)
            .expect("initial crypto can generate retry secret");

        let mut packet_in_place = Vec::with_capacity(header.len() + payload.len());
        packet_in_place.extend_from_slice(header);
        packet_in_place.extend_from_slice(&payload[0..payload.len() - HYPHAE_AEAD_TAG_LEN]);
        packet_in_place.extend_from_slice(&[0u8; HYPHAE_AEAD_TAG_LEN]);
        initial_crypto.encrypt_in_place(&retry_key, 0, b"", &mut packet_in_place)
            .expect("initial crypto can encrypt retry packet");

        payload[payload.len() - HYPHAE_AEAD_TAG_LEN..] == packet_in_place[packet_in_place.len() - HYPHAE_AEAD_TAG_LEN..]
    }

    #[allow(unused_variables)]
    fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> Result<(), crypto::ExportKeyingMaterialError> {
        // Check if handshake is completed
        let handshake = self.handshake.as_ref()
            .ok_or(crypto::ExportKeyingMaterialError)?;
        
        if !handshake.is_handshake_finished() {
            return Err(crypto::ExportKeyingMaterialError);
        }
        
        // Export the keying material using Hyphae's implementation
        handshake.export_keying_material(label, context, output)
            .map_err(|_| crypto::ExportKeyingMaterialError)
    }
}

fn handshake_failed<T> (_: T) -> Error {
    Error::HandshakeFailed
}
