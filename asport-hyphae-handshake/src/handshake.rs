use std::{iter::once, mem, ops::Deref};

use rand_core::{CryptoRng, RngCore};

use crate::{buffer::{AppendOnlyBuffer, Buffer, BufferFullError, MaxLenBuffer, VarIntSize, VarLengthPrefixBuffer}, crypto::{CryptoBackend, CryptoError, NoiseHandshake, SecretKeySetup, SymmetricKey, TransportCrypto}, customization::{HandshakeConfig, HandshakeDriver, HandshakeInfo}, Error};

impl From<BufferFullError> for Error {
    fn from(_: BufferFullError) -> Self {
        Self::BufferSize
    }
}

impl From<CryptoError> for Error {
    fn from(value: CryptoError) -> Self {
        match value {
            CryptoError::DecryptionFailed => Error::HandshakeFailed,
            _ => Error::Internal,
        }
    }
}

#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub enum HandshakeVersion {
    Version1,
}

impl HandshakeVersion {
    pub fn label(self) -> &'static [u8] {
        match self {
            HandshakeVersion::Version1 => b"hyphae-h-v1",
        }
    }

    pub fn id(self) -> u8 {
        match self {
            HandshakeVersion::Version1 => 1,
        }
    }
}

pub const HYPHAE_INITIAL_SECRET_HKDF_LABEL: &'static [u8] = b"hyphae initial";
pub const HYPHAE_RETRY_SECRET_HKDF_LABEL: &'static [u8] = b"hyphae retry";
pub const HYPHAE_KEY_ASK_LABEL: &'static [u8] = b"hyphae key";
pub const HYPHAE_INIT_DATA_HKDF_LABEL: &'static [u8] = b"init data";
pub const HYPHAE_RESP_DATA_HKDF_LABEL: &'static [u8] = b"resp data";
pub const HYPHAE_INIT_HP_HKDF_LABEL: &'static [u8] = b"init hp";
pub const HYPHAE_RESP_HP_HKDF_LABEL: &'static [u8] = b"resp hp";

#[cfg(feature = "alloc")]
pub struct AllocHyphaeHandshake<T: HandshakeDriver, B: CryptoBackend, R: Deref<Target = B>> {
    crypto: R,
    phase: AllocHyphaeHandshakePhase,
    handshake_driver: Box<T>,
    noise_handshake: Box<B::NoiseHandshake>,
    peer_transport_params: Option<Vec<u8>>,
    peer_zero_rtt_accepted: Option<bool>,
    next_level_secret_ready: bool,
}

#[cfg(feature = "alloc")]
impl <T: HandshakeDriver, B: CryptoBackend, R: Deref<Target = B>> AllocHyphaeHandshake<T, B, R> {
    pub fn new_initiator<C> (handshake_config: &C, crypto: R, version: HandshakeVersion, transport_label: &[u8], transport_params: Vec<u8>, server_name: &str) -> Result<Self, Error>
    where
        C: HandshakeConfig<Driver = T>,
    {
        let mut preamble = Vec::new();
        handshake_config.initiator_preamble(&mut preamble)?;

        let mut noise_handshake = Box::new(crypto.new_handshake()?);
        let mut noise_wrapper = NoiseHandshakeWrapper::wrap_init(noise_handshake.as_mut(), version, transport_label, &preamble, true);
        let handshake_driver = Box::new(handshake_config.new_initiator(server_name, &mut noise_wrapper)?);

        if noise_handshake.is_reset() {
            return Err(Error::Internal);
        }

        let phase = if preamble.is_empty() {
            AllocHyphaeHandshakePhase::Initiator(
                AllocHyphaeInitiatorPhase::WriteInitiatorConfigNoise { transport_params }
            )
        } else {
            AllocHyphaeHandshakePhase::Initiator(
                AllocHyphaeInitiatorPhase::WritePreamble { preamble, transport_params }
            )
        };

        Ok(Self {
            crypto,
            phase,
            handshake_driver,
            noise_handshake,
            peer_transport_params: None,
            peer_zero_rtt_accepted: None,
            next_level_secret_ready: false,
        })
    }

    pub fn new_responder<C> (handshake_config: &C, crypto: R, version: HandshakeVersion, transport_label: &[u8], transport_params: Vec<u8>, mut first_message: Vec<u8>) -> Result<Self, Error>
    where
        C: HandshakeConfig<Driver = T>,
    {
        let mut noise_handshake = Box::new(crypto.new_handshake()?);

        let preamble = if MessageReader::decode_message_type(&first_message)? == HandshakeMessage::Preamble {
            let reader = MessageReader::decode_in_place(&mut first_message, HandshakeMessage::Preamble, noise_handshake.as_mut())?;
            reader.payload()?
        } else {
            &[]
        };

        let mut noise_wrapper = NoiseHandshakeWrapper::wrap_init(noise_handshake.as_mut(), version, transport_label, preamble, false);
        let handshake_driver = Box::new(handshake_config.new_responder(preamble, &mut noise_wrapper)?);

        if noise_handshake.is_reset() {
            return Err(Error::Internal);
        }

        let phase = AllocHyphaeHandshakePhase::Responder(
            AllocHyphaeResponderPhase::ReadInitiatorConfigNoise { transport_params }
        );

        let mut this = Self {
            crypto,
            phase,
            handshake_driver,
            noise_handshake,
            peer_transport_params: None,
            peer_zero_rtt_accepted: None,
            next_level_secret_ready: false,
        };

        if preamble.is_empty() {
            this.read_message(first_message)?
        }
        
        Ok(this)
    }

    pub fn peer_params(&self) -> Option<&[u8]> {
        self.peer_transport_params.as_ref().map(Vec::as_slice)
    }

    /// Returns true once the Noise portion of the handshake is finished
    /// and 1-RTT keys are available.
    /// 
    /// Peers will still exchange final messages but this happens in the
    /// 1-RTT packet space and cannot fail the handshake.
    /// 
    /// The Noise handshake state and its key material will be discarded
    /// after a peer sends its final message.
    pub fn is_handshake_finished(&self) -> bool {
        match self.phase {
            AllocHyphaeHandshakePhase::Initiator(AllocHyphaeInitiatorPhase::SendFinal { .. }) => true,
            AllocHyphaeHandshakePhase::Responder(AllocHyphaeResponderPhase::SendFinal { .. }) => true,
            AllocHyphaeHandshakePhase::Initiator(AllocHyphaeInitiatorPhase::RecvFinal) => true,
            AllocHyphaeHandshakePhase::Responder(AllocHyphaeResponderPhase::RecvFinal) => true,
            AllocHyphaeHandshakePhase::Initiator(AllocHyphaeInitiatorPhase::Finalized) => true,
            AllocHyphaeHandshakePhase::Responder(AllocHyphaeResponderPhase::Finalized) => true,
            _ => false,
        }
    }

    /// Returns true once this peer has sent and received its final
    /// message.
    /// 
    /// At this point, all handshake state can be discarded.
    pub fn is_handshake_finalized(&self) -> bool {
        //todo, broken, fix this - also need to dispose of noise handshake before reading each other's finals to clear keys in case the other side never responds
        match self.phase {
            AllocHyphaeHandshakePhase::Initiator(AllocHyphaeInitiatorPhase::Finalized) => true,
            AllocHyphaeHandshakePhase::Responder(AllocHyphaeResponderPhase::Finalized) => true,
            _ => false,
        }
    }

    pub fn is_initiator(&self) -> bool {
        self.noise_handshake.is_initiator()
    }

    pub fn remote_public(&self) -> Option<&[u8]> {
        self.noise_handshake.remote_public()
    }

    pub fn final_handshake_hash(&self) -> Option<&[u8]> {
        match self.noise_handshake.is_finished() {
            true => Some(self.noise_handshake.handshake_hash()),
            false => None,
        }
    }

    pub fn handshake_driver(&self) -> &T {
        &self.handshake_driver
    }

    pub fn zero_rtt_accepted(&self) -> Option<bool> {
        self.peer_zero_rtt_accepted
    }

    pub fn next_level_secret_ready(&self) -> bool {
        self.next_level_secret_ready
    }

    pub fn next_level_secret(&mut self, level_secret: &mut SymmetricKey) -> Result<(), Error> {
        if self.next_level_secret_ready {
            self.noise_handshake.get_ask(HYPHAE_KEY_ASK_LABEL, level_secret)?;
            self.next_level_secret_ready = false;
            Ok(())
        } else {
            Err(Error::Internal)
        }
    }

    pub fn transport_crypto(&self) -> Result<B::TransportCrypto, Error> {
        Ok(self.crypto.transport_crypto(&self.noise_handshake)?)
    }

    pub fn export_1rtt_rekey(&mut self, rekey: &mut B::TransportRekey) -> Result<(), Error> {
        Ok(self.crypto.export_1rtt_rekey(&mut self.noise_handshake, rekey)?)
    }

    /// Export keying material for application use, similar to TLS export_keying_material
    /// 
    /// This function allows applications to derive additional key material from
    /// the completed handshake state. The derived keys are cryptographically
    /// bound to the handshake and can be used for application-specific purposes.
    /// 
    /// # Parameters
    /// * `label` - An application-defined label to distinguish different uses
    /// * `context` - Optional context information to bind into the derivation
    /// * `output` - Buffer to receive the derived key material
    /// 
    /// # Returns
    /// * `Ok(())` on success
    /// * `Err(Error::Internal)` if called before handshake completion
    /// 
    /// # Example
    /// ```rust,ignore
    /// let mut app_key = vec![0u8; 32];
    /// handshake.export_keying_material(b"my-app-key", b"session-123", &mut app_key)?;
    /// ```
    pub fn export_keying_material(&self, label: &[u8], context: &[u8], output: &mut [u8]) -> Result<(), Error> {
        if !self.is_handshake_finished() {
            return Err(Error::Internal);
        }
        
        self.noise_handshake.export_keying_material(label, context, output)?;
        Ok(())
    }

    pub fn read_message(&mut self, message: Vec<u8>) -> Result<(), Error> {
        match self.phase {
            AllocHyphaeHandshakePhase::Initiator(_) => self.initiator_read_message(message),
            AllocHyphaeHandshakePhase::Responder(_) => self.responder_read_message(message),
        }
    }

    pub fn write_message(&mut self, buffer: &mut impl Buffer) -> Result<(), Error> {
        match self.phase {
            AllocHyphaeHandshakePhase::Initiator(_) => self.initiator_write_message(buffer),
            AllocHyphaeHandshakePhase::Responder(_) => self.responder_write_message(buffer),
        }
    }

    fn initiator_write_message(&mut self, buffer: &mut impl Buffer) -> Result<(), Error> {
        let AllocHyphaeHandshakePhase::Initiator(ref mut phase) = self.phase else {
            unreachable!();
        };

        match phase {
            AllocHyphaeInitiatorPhase::WritePreamble { preamble, transport_params } => {
                write_preamble(buffer, preamble.as_slice())?;
                *phase = AllocHyphaeInitiatorPhase::WriteInitiatorConfigNoise {
                    transport_params: mem::take(transport_params),
                };
                Ok(())
            },

            AllocHyphaeInitiatorPhase::WriteInitiatorConfigNoise { transport_params } => {
                let transport_params = mem::take(transport_params);
                write_initiator_initial(buffer, self.noise_handshake.as_mut(), transport_params.as_slice(), self.handshake_driver.as_mut(), phase.message_position()?)?;
                *phase = AllocHyphaeInitiatorPhase::ReadResponderConfigNoise;
                Ok(())
            },

            AllocHyphaeInitiatorPhase::Noise { .. } if self.noise_handshake.is_my_turn() => self.write_noise_message(buffer),

            AllocHyphaeInitiatorPhase::SendFinal { received_final } => {
                if self.next_level_secret_ready {
                    return Err(Error::Internal); // Todo, maybe just always check this for safety
                }

                write_final(buffer, self.noise_handshake.as_mut(), self.handshake_driver.as_mut())?;
                // Todo, destroy noise handshake state here.
                match received_final {
                    true => *phase = AllocHyphaeInitiatorPhase::Finalized,
                    false => *phase = AllocHyphaeInitiatorPhase::RecvFinal,
                }
                Ok(())
            },

            _ => Ok(())
        }
    }

    fn responder_read_message(&mut self, mut message: Vec<u8>) -> Result<(), Error> {
        let AllocHyphaeHandshakePhase::Responder(ref mut phase) = self.phase else {
            unreachable!();
        };

        match phase {
            AllocHyphaeResponderPhase::ReadInitiatorConfigNoise { transport_params } => {
                let transport_params = mem::take(transport_params);

                let prev_hash = self.noise_handshake.handshake_hash().to_vec();
                let reader = MessageReader::decode_in_place(&mut message, HandshakeMessage::Initial, self.noise_handshake.as_mut())?;
                let (peer_transport_params, app_payload) = reader.initial_init_payloads()?;
                self.peer_transport_params = Some(peer_transport_params.to_vec());

                let mut noise_wrapper = NoiseHandshakeWrapper::wrap_payload(self.noise_handshake.as_mut(),Some(phase.message_position()?), Some(&prev_hash));
                self.handshake_driver.read_noise_payload(app_payload, &mut noise_wrapper)?;

                *phase = AllocHyphaeResponderPhase::WriteResponderConfigNoise {
                    transport_params,
                };

                Ok(())
            },

            AllocHyphaeResponderPhase::Noise { .. } if !self.noise_handshake.is_my_turn() => self.read_noise_message(message),

            AllocHyphaeResponderPhase::SendFinal { received_final: false } |
            AllocHyphaeResponderPhase::RecvFinal => {
                if self.next_level_secret_ready {
                    return Err(Error::Internal);
                }

                let prev_hash = self.noise_handshake.handshake_hash().to_vec();
                let reader = MessageReader::decode_in_place(&mut message, HandshakeMessage::Final, self.noise_handshake.as_mut())?;
                let final_payload = reader.final_payload()?;
                let mut noise_wrapper = NoiseHandshakeWrapper::wrap_payload(self.noise_handshake.as_mut(), None, Some(&prev_hash));
                self.handshake_driver.read_final_payload(final_payload, &mut noise_wrapper)?;

                match phase {
                    AllocHyphaeResponderPhase::SendFinal { received_final: false } => {
                        *phase = AllocHyphaeResponderPhase::SendFinal { received_final: true }
                    },
                    _ => *phase = AllocHyphaeResponderPhase::Finalized,
                }

                Ok(())
            },

            _ => Err(Error::HandshakeFailed)
        }
    }


    fn responder_write_message(&mut self, buffer: &mut impl Buffer) -> Result<(), Error> {
        let AllocHyphaeHandshakePhase::Responder(ref mut phase) = self.phase else {
            unreachable!();
        };

        match phase {
            AllocHyphaeResponderPhase::WriteResponderConfigNoise { transport_params } => {
                // Build deferred payload.
                let transport_params = mem::take(transport_params);
                let mut deferred_payload = Vec::new();
                write_responder_deferred_payload(&mut deferred_payload, self.noise_handshake.as_mut(), transport_params.as_slice(), false, self.handshake_driver.as_mut(), phase.message_position()?)?;

                let crypto = self.crypto.transport_crypto(&self.noise_handshake)?;
                let mut deferred_payload_hash = crypto.zeros_hash();
                crypto.hash_into(&deferred_payload[1..], &mut deferred_payload_hash);

                // Build initial message with deferred payload hash.
                write_responder_initial(buffer, self.noise_handshake.as_mut(), &crypto.hash_as_slice(&deferred_payload_hash))?;

                *phase = AllocHyphaeResponderPhase::WriteResponderDeferredPayload {
                    deferred_payload,
                };

                self.next_level_secret_ready = true;

                Ok(())
            },

            AllocHyphaeResponderPhase::WriteResponderDeferredPayload { deferred_payload } => {
                if self.next_level_secret_ready {
                    return Err(Error::Internal);
                }

                buffer.extend_from_slice(&deferred_payload)?;
                *phase = AllocHyphaeResponderPhase::Noise { position: 3 };
                self.check_noise_finished()
            },

            AllocHyphaeResponderPhase::Noise { .. } if self.noise_handshake.is_my_turn() => self.write_noise_message(buffer),

            AllocHyphaeResponderPhase::SendFinal { received_final } => {
                if self.next_level_secret_ready {
                    return Err(Error::Internal); // Todo, maybe just always check this for safety
                }

                write_final(buffer, self.noise_handshake.as_mut(), self.handshake_driver.as_mut())?;
                // Todo, destroy noise handshake state here.
                match received_final {
                    true => *phase = AllocHyphaeResponderPhase::Finalized,
                    false => *phase = AllocHyphaeResponderPhase::RecvFinal,
                }
                Ok(())
            },

            _ => Ok(())
        }
    }

    fn initiator_read_message(&mut self, mut message: Vec<u8>) -> Result<(), Error> {
        let AllocHyphaeHandshakePhase::Initiator(ref mut phase) = self.phase else {
            unreachable!();
        };

        match phase {
            AllocHyphaeInitiatorPhase::ReadResponderConfigNoise => {
                let prev_noise_hash = self.noise_handshake.handshake_hash().to_vec();
                let reader = MessageReader::decode_in_place(&mut message, HandshakeMessage::Initial, self.noise_handshake.as_mut())?;
                let deferred_payload_hash = reader.initial_resp_payloads()?;

                *phase = AllocHyphaeInitiatorPhase::ReadResponderDeferredPayload {
                    deferred_payload_hash: deferred_payload_hash.to_vec(),
                    prev_noise_hash,
                };

                self.next_level_secret_ready = true;
                Ok(())
            },

            AllocHyphaeInitiatorPhase::ReadResponderDeferredPayload { deferred_payload_hash, prev_noise_hash } => {
                if self.next_level_secret_ready {
                    return Err(Error::Internal);
                }

                let prev_noise_hash = mem::take(prev_noise_hash);

                let reader = MessageReader::decode_in_place(&mut message, HandshakeMessage::DeferredPayload, self.noise_handshake.as_mut())?;

                let crypto = self.crypto.transport_crypto(&self.noise_handshake)?;
                let mut actual_payload_hash = crypto.zeros_hash();
                crypto.hash_into(reader.payload, &mut actual_payload_hash);
                if deferred_payload_hash.as_slice() != crypto.hash_as_slice(&actual_payload_hash) {
                    return Err(Error::HandshakeFailed);
                }

                let (peer_params, zero_rtt_acc, app_payload) = reader.deferred_resp_payloads()?;
                self.peer_zero_rtt_accepted = Some(zero_rtt_acc);

                let mut noise_wrapper = NoiseHandshakeWrapper::wrap_payload(self.noise_handshake.as_mut(), Some(phase.message_position()?), Some(&prev_noise_hash));
                self.handshake_driver.read_noise_payload(app_payload, &mut noise_wrapper)?;

                self.peer_transport_params = Some(peer_params.to_vec());
                *phase = AllocHyphaeInitiatorPhase::Noise { position: 3 };
                self.check_noise_finished()
            },

            AllocHyphaeInitiatorPhase::Noise { .. } if !self.noise_handshake.is_my_turn() => self.read_noise_message(message),

            AllocHyphaeInitiatorPhase::SendFinal { received_final: false } |
            AllocHyphaeInitiatorPhase::RecvFinal => {
                if self.next_level_secret_ready {
                    return Err(Error::Internal);
                }

                let reader = MessageReader::decode_in_place(&mut message, HandshakeMessage::Final, self.noise_handshake.as_mut())?;
                let final_payload = reader.final_payload()?;
                let mut noise_wrapper = NoiseHandshakeWrapper::wrap_payload(self.noise_handshake.as_mut(), None, None);
                self.handshake_driver.read_final_payload(final_payload, &mut noise_wrapper)?;

                match phase {
                    AllocHyphaeInitiatorPhase::SendFinal { received_final: false } => {
                        *phase = AllocHyphaeInitiatorPhase::SendFinal { received_final: true }
                    },
                    _ => *phase = AllocHyphaeInitiatorPhase::Finalized,
                }

                Ok(())
            },

            _ => Err(Error::HandshakeFailed),
        }
    }

    fn write_noise_message(&mut self, buffer: &mut impl Buffer) -> Result<(), Error> {
        write_noise(buffer, self.noise_handshake.as_mut(), self.handshake_driver.as_mut(), self.phase.message_position()?)?;
        self.phase.advance_message_position()?;
        self.check_noise_finished()
    }

    fn read_noise_message(&mut self, mut message: Vec<u8>) -> Result<(), Error> {
        let prev_hash = self.noise_handshake.handshake_hash().to_vec();
        let reader = MessageReader::decode_in_place(&mut message, HandshakeMessage::Noise, self.noise_handshake.as_mut())?;
        let mut noise_wrapper = NoiseHandshakeWrapper::wrap_payload(self.noise_handshake.as_mut(), Some(self.phase.message_position()?), Some(&prev_hash));
        self.handshake_driver.read_noise_payload(reader.payload()?, &mut noise_wrapper)?;
        self.phase.advance_message_position()?;
        self.check_noise_finished()
    }

    fn check_noise_finished(&mut self) -> Result<(), Error> {
        match &mut self.phase {
            AllocHyphaeHandshakePhase::Initiator(AllocHyphaeInitiatorPhase::Noise { .. }) => {
                if self.noise_handshake.is_finished() {
                    self.phase = AllocHyphaeHandshakePhase::Initiator(AllocHyphaeInitiatorPhase::SendFinal { received_final: false });
                }
            },
            AllocHyphaeHandshakePhase::Responder(AllocHyphaeResponderPhase::Noise { .. }) => {
                if self.noise_handshake.is_finished() {
                    self.phase = AllocHyphaeHandshakePhase::Responder(AllocHyphaeResponderPhase::SendFinal { received_final: false });
                }
            },
            _ => return Err(Error::Internal)
        }

        if self.noise_handshake.is_finished() {
            self.next_level_secret_ready = true;
        }
        Ok(())
    }
}

enum AllocHyphaeHandshakePhase {
    Initiator (AllocHyphaeInitiatorPhase),
    Responder (AllocHyphaeResponderPhase),
}

impl AllocHyphaeHandshakePhase {
    pub fn message_position(&self) -> Result<u8, Error> {
        match self {
            AllocHyphaeHandshakePhase::Initiator(phase) => phase.message_position(),
            AllocHyphaeHandshakePhase::Responder(phase) => phase.message_position(),
        }
    }

    pub fn advance_message_position(&mut self) -> Result<(), Error> {
        let position = match self {
            AllocHyphaeHandshakePhase::Initiator(AllocHyphaeInitiatorPhase::Noise { position }) => position,
            AllocHyphaeHandshakePhase::Responder(AllocHyphaeResponderPhase::Noise { position }) => position,
            _ => return Err(Error::Internal)
        };
        *position = position.checked_add(1).ok_or(Error::Internal)?;
        Ok(())
    }
}

enum AllocHyphaeInitiatorPhase {
    WritePreamble {
        preamble: Vec<u8>,
        transport_params: Vec<u8>,
    },
    WriteInitiatorConfigNoise {
        transport_params: Vec<u8>,
    },
    ReadResponderConfigNoise,
    ReadResponderDeferredPayload {
        deferred_payload_hash: Vec<u8>,
        prev_noise_hash: Vec<u8>,
    },
    Noise {
        position: u8,
    },
    SendFinal {
        received_final: bool,
    },
    RecvFinal,
    Finalized,
}

impl AllocHyphaeInitiatorPhase {
    pub fn message_position(&self) -> Result<u8, Error> {
        match self {
            AllocHyphaeInitiatorPhase::WriteInitiatorConfigNoise { .. } => Ok(1),
            AllocHyphaeInitiatorPhase::ReadResponderDeferredPayload { .. } => Ok(2),
            AllocHyphaeInitiatorPhase::Noise { position } => Ok(*position),
            _ => Err(Error::Internal),
        }
    }
}

enum AllocHyphaeResponderPhase {
    ReadInitiatorConfigNoise {
        transport_params: Vec<u8>,
    },
    WriteResponderConfigNoise {
        transport_params: Vec<u8>,
    },
    WriteResponderDeferredPayload {
        deferred_payload: Vec<u8>,
    },
    Noise {
        position: u8,
    },
    SendFinal {
        received_final: bool,
    },
    RecvFinal,
    Finalized,
}

impl AllocHyphaeResponderPhase {
    pub fn message_position(&self) -> Result<u8, Error> {
        match self {
            AllocHyphaeResponderPhase::ReadInitiatorConfigNoise { .. } => Ok(1),
            AllocHyphaeResponderPhase::WriteResponderConfigNoise { .. } => Ok(2),
            AllocHyphaeResponderPhase::Noise { position } => Ok(*position),
            _ => Err(Error::Internal),
        }
    }
}

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum HandshakeMessage {
    Preamble = 1,
    Initial = 2,
    DeferredPayload = 3,
    Noise = 4,
    FinalPayload = 126,
    Final = 127,
    Failed = 255,
}

impl HandshakeMessage {
    pub fn from_id(id: u8) -> Result<Self, Error> {
        match id {
            x if x == Self::Preamble as u8 => Ok(Self::Preamble),
            x if x == Self::Initial as u8 => Ok(Self::Initial),
            x if x == Self::DeferredPayload as u8 => Ok(Self::DeferredPayload),
            x if x == Self::Noise as u8 => Ok(Self::Noise),
            x if x == Self::Final as u8 => Ok(Self::Final),
            x if x == Self::FinalPayload as u8 => Ok(Self::FinalPayload),
            x if x == Self::Failed as u8 => Ok(Self::Failed),
            _ => Err(Error::HandshakeFailed)
        }
    }

    pub fn is_encrypted(self) -> bool {
        match self {
            HandshakeMessage::Initial |
            HandshakeMessage::Noise => true,
            _ => false,
        }
    }

    pub fn has_compound_payload(self) -> bool {
        match self {
            HandshakeMessage::Initial |
            HandshakeMessage::DeferredPayload |
            HandshakeMessage::FinalPayload => true,
            _ => false,
        }
    }

    pub fn has_payload(self) -> Option<bool> {
        match self {
            HandshakeMessage::Preamble => Some(true),
            HandshakeMessage::Initial => Some(true),
            HandshakeMessage::DeferredPayload => Some(true),
            HandshakeMessage::Noise => None,
            HandshakeMessage::FinalPayload => Some(true),
            HandshakeMessage::Final => Some(false),
            HandshakeMessage::Failed => Some(false),
        }
    }
}

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum PayloadFrame {
    Padding = 0,
    ApplicationPayload = 1,
    TransportParameters = 2,
    DeferredPayloadHash = 3,
    ZeroRttAccepted = 64,
}

impl PayloadFrame {
    /// Optional frame lower bound (inclusive).
    /// 
    /// Optional frames can be ignored if they are not supported. These
    /// frames must begin with a `VarInt` length prefix and not be
    /// essential to the handshake. Frame IDs less than the optional
    /// base must be recognized or the handshake will fail.
    /// 
    /// This feature isn't used yet, but is here to allow extensibility
    /// without revving the handshake version.
    const OPTIONAL_BASE: u8 = 128;

    fn ok_in(self, message: HandshakeMessage, from_initiator: bool) -> Result<(), Error> {
        match (message, from_initiator, self) {
            (HandshakeMessage::Initial, true, Self::Padding) => Ok(()),
            (HandshakeMessage::Initial, true, Self::TransportParameters) => Ok(()),
            (HandshakeMessage::Initial, true, Self::ApplicationPayload) => Ok(()),
            (HandshakeMessage::Initial, false, Self::Padding) => Ok(()),
            (HandshakeMessage::Initial, false, Self::DeferredPayloadHash) => Ok(()),
            (HandshakeMessage::DeferredPayload, false, Self::Padding) => Ok(()),
            (HandshakeMessage::DeferredPayload, false, Self::TransportParameters) => Ok(()),
            (HandshakeMessage::DeferredPayload, false, Self::ZeroRttAccepted) => Ok(()),
            (HandshakeMessage::DeferredPayload, false, Self::ApplicationPayload) => Ok(()),
            (HandshakeMessage::FinalPayload, false, Self::ApplicationPayload) => Ok(()),
            _ => Err(Error::HandshakeFailed)
        }
    }

    fn from_id(frame_id: u8) -> Result<Option<Self>, Error> {
        match frame_id {
            id if id == Self::Padding as u8 => Ok(Some(Self::Padding)),
            id if id == Self::ApplicationPayload as u8 => Ok(Some(Self::ApplicationPayload)),
            id if id == Self::TransportParameters as u8 => Ok(Some(Self::TransportParameters)),
            id if id == Self::DeferredPayloadHash as u8 => Ok(Some(Self::DeferredPayloadHash)),
            id if id == Self::ZeroRttAccepted as u8 => Ok(Some(Self::ZeroRttAccepted)),
            id if id >= Self::OPTIONAL_BASE => Ok(None),
            _ => Err(Error::HandshakeFailed),
        }
    }

    fn get_frame_payload(this: Option<Self>, mut remaining: &[u8]) -> Result<(&[u8], &[u8]), Error> {
        let payload_len = match this {
            Some(Self::ApplicationPayload) => remaining.len(),
            Some(Self::DeferredPayloadHash) => remaining.len(),
            Some(Self::Padding) => 0,
            Some(Self::ZeroRttAccepted) => 0,
            None | Some(Self::TransportParameters) => {
                // todo, better varint decoding
                let prefix_len = VarIntSize::from_msb(remaining.get(0).copied().ok_or(Error::HandshakeFailed)?);
                if remaining.len() < prefix_len.len() {
                    return Err(Error::HandshakeFailed);
                }
                let (prefix, r) = remaining.split_at(prefix_len.len());
                remaining = r;
                let mut prefix64 = [0u8; 8];
                prefix64[8 - prefix.len()..].copy_from_slice(prefix);
                prefix64[8 - prefix.len()] &= !0xC0;
                u64::from_be_bytes(prefix64).try_into().map_err(|_| Error::HandshakeFailed)?
            }
        };
        if payload_len > remaining.len() {
            return Err(Error::HandshakeFailed)
        }
        Ok(remaining.split_at(payload_len))
    }

    pub fn next_frame(remaining: &[u8], message: HandshakeMessage, from_initiator: bool) -> Result<Option<(Self, &[u8], &[u8])>, Error> {
        let Some(frame_id) = remaining.get(0).cloned() else {
            return Ok(None);
        };

        let frame_type = Self::from_id(frame_id)?;
        if let Some(frame_type) = frame_type {
            frame_type.ok_in(message, from_initiator)?;
        }
        let (frame_payload, remaining) = Self::get_frame_payload(frame_type, &remaining[1..])?;

        match frame_type {
            Some(frame_type) if frame_type != Self::Padding =>
                Ok(Some((frame_type, frame_payload, remaining))),

            _ => Self::next_frame(remaining, message, from_initiator), // todo, this could be an issue if it isn't a tail call
        }
    }
    
}

struct NoiseHandshakeWrapper<'a, X: NoiseHandshake> {
    inner: &'a mut X,
    init_info: Option<(HandshakeVersion, &'a [u8], &'a [u8])>,
    initiator: Option<bool>,
    position: Option<u8>,
    prev_hash: Option<&'a [u8]>,
}

impl <'a, X: NoiseHandshake> NoiseHandshakeWrapper<'a, X> {
    pub fn wrap_init(inner: &'a mut X, version: HandshakeVersion, transport_label: &'a [u8], preamble: &'a [u8], initiator: bool) -> Self {
        Self {
            inner,
            init_info: Some((version, transport_label, preamble)),
            initiator: Some(initiator),
            position: None,
            prev_hash: None,
        }
    }

    pub fn wrap_payload(inner: &'a mut X, position: Option<u8>, prev_hash: Option<&'a [u8]>) -> Self {
        Self {
            inner,
            init_info: None,
            initiator: None,
            position,
            prev_hash,
        }
    }
}

impl <X: NoiseHandshake> HandshakeInfo for NoiseHandshakeWrapper<'_, X> {
    fn initialize(&mut self, rng: &mut (impl CryptoRng + RngCore), protocol: &str, prologue: &[u8], s: Option<SecretKeySetup>, rs: Option<&[u8]>) -> Result<(), CryptoError> {
        let Some(initiator) = self.initiator else {
            return Err(CryptoError::Internal);
        };
        let Some((version, transport_label, preamble)) = self.init_info else {
            return Err(CryptoError::Internal);
        };
        let Ok(preamble_len) = u16::try_from(preamble.len()) else {
            return Err(CryptoError::Internal);
        };
        let preamble_len_le = preamble_len.to_le_bytes();

        if !self.inner.is_reset() {
            return Err(CryptoError::Internal);
        }

        let handshake_prologue =
            once(version.label())
            .chain(once(b".".as_slice()))
            .chain(once(transport_label))
            .chain(once(b".".as_slice()))
            .chain(once(preamble_len_le.as_slice()))
            .chain(once(preamble))
            .chain(once(prologue));

        self.inner.initialize(rng, protocol, initiator, handshake_prologue, s, rs)
    }

    fn set_token(&mut self, _token: &str, _value: &[u8]) -> Result<(), CryptoError> {
        Err(CryptoError::Internal)
    }

    fn is_initiator(&self) -> bool {
        if self.inner.is_reset() {
            self.initiator.unwrap_or_default()
        } else {
            self.inner.is_initiator()
        }
    }

    fn is_finished(&self) -> bool {
        self.inner.is_finished()
    }
    
    fn handshake_position(&self) -> Option<u8> {
        self.position
    }
    
    fn remote_public(&self) -> Option<&[u8]> {
        self.inner.remote_public()
    }

    fn prev_handshake_hash(&self) -> Option<&[u8]> {
        self.prev_hash.or_else(|| Some(self.inner.handshake_hash()))
    }

    fn final_handshake_hash(&self) -> Option<&[u8]> {
        match self.inner.is_finished() {
            true => Some(self.inner.handshake_hash()),
            false => None,
        }
    }
}

struct MessageReader<'a> {
    payload: &'a [u8],
    message_type: HandshakeMessage,
}

impl <'a> MessageReader<'a> {
    pub fn decode_message_type(buffer: &[u8]) -> Result<HandshakeMessage, Error> {
        if buffer.is_empty() {
            return Err(Error::HandshakeFailed);
        }

        HandshakeMessage::from_id(buffer[0])
    }

    pub fn decode_in_place(buffer: &'a mut [u8], expect: HandshakeMessage, noise: &mut impl NoiseHandshake) -> Result<Self, Error> {
        let message_type = Self::decode_message_type(buffer)?;
        let buffer = &mut buffer[1..];

        let expected = match expect {
            HandshakeMessage::Final => 
                message_type == HandshakeMessage::Final ||
                message_type == HandshakeMessage::FinalPayload,
            expect => expect == message_type,
        };
        if !expected {
            return Err(Error::HandshakeFailed);
        }
        
        // Decrypt Noise messages in place, extract payload.
        let payload = if message_type.is_encrypted() {
            noise.read_message_in_place(buffer)?
        } else {
            buffer
        };

        // Check compound payload version.
        if message_type.has_compound_payload() &&
           (payload.is_empty() || payload[0] != HandshakeVersion::Version1.id())
        {
            return Err(Error::HandshakeFailed);
        }

        // Verify payload expectation.
        if let Some(has_payload) = message_type.has_payload() {
            if has_payload == payload.is_empty() {
                return Err(Error::HandshakeFailed);
            }
        }

        Ok(Self {
            payload,
            message_type,
        })
    }

    /// Return the payload from messages without a compound payload.
    pub fn payload(&self) -> Result<&'a [u8], Error> {
        if self.message_type.has_compound_payload() {
            return Err(Error::Internal);
        }
        Ok(self.payload)
    }

    /// Return `(transport_params, application_payload)` from the
    /// initiator's initial message.
    pub fn initial_init_payloads(&self) -> Result<(&'a [u8], &'a [u8]), Error> {
        if self.message_type != HandshakeMessage::Initial {
            return Err(Error::Internal);
        }

        let mut frame_cursor = &self.payload[1..];
        let mut transport_params = None;
        let mut application_payload = None;

        loop {
            let Some((frame, payload, remaining)) = PayloadFrame::next_frame(frame_cursor, self.message_type, true)? else {
                break;
            };
            match frame {
                PayloadFrame::ApplicationPayload if application_payload.is_some() => return Err(Error::HandshakeFailed),
                PayloadFrame::ApplicationPayload => application_payload = Some(payload),
                PayloadFrame::TransportParameters if transport_params.is_some() => return Err(Error::HandshakeFailed),
                PayloadFrame::TransportParameters => transport_params = Some(payload),
                _ => {}
            }
            frame_cursor = remaining;
        }

        if let Some(true) = application_payload.map(|s| s.is_empty()) {
            return Err(Error::HandshakeFailed);
        }

        application_payload.get_or_insert(&[]);

        match (transport_params, application_payload) {
            (Some(tp), Some(ap)) => Ok((tp, ap)),
            _ => Err(Error::HandshakeFailed)
        }
    }

    /// Return the deferred payload hash from the responder's initial
    /// message.
    pub fn initial_resp_payloads(&self) -> Result<&'a [u8], Error> {
        if self.message_type != HandshakeMessage::Initial {
            return Err(Error::Internal);
        }

        let mut frame_cursor = &self.payload[1..];
        let mut deferred_hash = None;

        loop {
            let Some((frame, payload, remaining)) = PayloadFrame::next_frame(frame_cursor, self.message_type, false)? else {
                break;
            };
            match frame {
                PayloadFrame::DeferredPayloadHash if deferred_hash.is_some() => return Err(Error::HandshakeFailed),
                PayloadFrame::DeferredPayloadHash => deferred_hash = Some(payload),
                _ => {}
            }
            frame_cursor = remaining;
        }
        
        if let Some(true) = deferred_hash.map(|s| s.is_empty()) {
            return Err(Error::HandshakeFailed);
        }

        match deferred_hash {
            Some(dh) => Ok(dh),
            _ => Err(Error::HandshakeFailed)
        }
    }

    /// Return `(transport_params, zero_rtt_accepted, application_payload)`
    /// from the responder's deferred payload message.
    pub fn deferred_resp_payloads(&self) -> Result<(&'a [u8], bool, &'a [u8]), Error> {
        if self.message_type != HandshakeMessage::DeferredPayload {
            return Err(Error::Internal);
        }

        let mut frame_cursor = &self.payload[1..];
        let mut transport_params = None;
        let mut application_payload = None;
        let mut zero_rtt_accepted = None;

        loop {
            let Some((frame, payload, remaining)) = PayloadFrame::next_frame(frame_cursor, self.message_type, false)? else {
                break;
            };
            match frame {
                PayloadFrame::ApplicationPayload if application_payload.is_some() => return Err(Error::HandshakeFailed),
                PayloadFrame::ApplicationPayload => application_payload = Some(payload),
                PayloadFrame::TransportParameters if transport_params.is_some() => return Err(Error::HandshakeFailed),
                PayloadFrame::TransportParameters => transport_params = Some(payload),
                PayloadFrame::ZeroRttAccepted if zero_rtt_accepted.is_some() => return Err(Error::HandshakeFailed),
                PayloadFrame::ZeroRttAccepted => zero_rtt_accepted = Some(true),
                _ => {}
            }
            frame_cursor = remaining;
        }
        
        if let Some(true) = application_payload.map(|s| s.is_empty()) {
            return Err(Error::HandshakeFailed);
        }

        application_payload.get_or_insert(&[]);
        zero_rtt_accepted.get_or_insert(false);

        match (transport_params, zero_rtt_accepted, application_payload) {
            (Some(tp), Some(zrtt), Some(ap)) => Ok((tp, zrtt, ap)),
            _ => Err(Error::HandshakeFailed)
        }
    }

    /// Return the final message's payload or an empty slice if one
    /// wasn't sent.
    pub fn final_payload(&self) -> Result<&'a [u8], Error> {
        match self.message_type {
            HandshakeMessage::Final => return Ok(&[]),
            HandshakeMessage::FinalPayload => {},
            _ => return Err(Error::Internal),
        }

        let mut frame_cursor = &self.payload[1..];
        let mut final_payload = None;

        loop {
            let Some((frame, payload, remaining)) = PayloadFrame::next_frame(frame_cursor, self.message_type, false)? else {
                break;
            };
            match frame {
                PayloadFrame::ApplicationPayload if final_payload.is_some() => return Err(Error::HandshakeFailed),
                PayloadFrame::ApplicationPayload => final_payload = Some(payload),
                _ => {}
            }
            frame_cursor = remaining;
        }

        match final_payload {
            Some(fp) => Ok(fp),
            _ => Err(Error::HandshakeFailed)
        }
    }
}

fn write_preamble(buffer: &mut impl Buffer, preamble: &[u8]) -> Result<(), Error> {
    let mut buffer = MaxLenBuffer::new(buffer, u16::MAX as usize)?;
    buffer.push(HandshakeMessage::Preamble as u8)?;
    buffer.extend_from_slice(preamble)?;
    Ok(())
}

fn write_initiator_initial(buffer: &mut impl Buffer, noise: &mut impl NoiseHandshake, transport_params: &[u8], driver: &mut impl HandshakeDriver, position: u8) -> Result<(), Error> {
    let mut buffer = MaxLenBuffer::new(buffer, u16::MAX as usize)?;
    let (token_padding, tag_padding) = noise.next_message_layout()?;
    buffer.push(HandshakeMessage::Initial as u8)?;
    insert_padding(&mut buffer, token_padding)?;
    buffer.push(HandshakeVersion::Version1.id())?;
    insert_varlen_frame(&mut buffer, PayloadFrame::TransportParameters, transport_params)?;
    insert_application_payload(&mut buffer, noise, driver, Some(position))?;
    insert_padding(&mut buffer, tag_padding)?;
    noise.write_message_in_place(&mut buffer.as_mut()[1..])?;
    Ok(())
}

fn write_responder_initial(buffer: &mut impl Buffer, noise: &mut impl NoiseHandshake, deferred_payload_hash: &[u8]) -> Result<(), Error> {
    let mut buffer = MaxLenBuffer::new(buffer, u16::MAX as usize)?;
    let (token_padding, tag_padding) = noise.next_message_layout()?;
    buffer.push(HandshakeMessage::Initial as u8)?;
    insert_padding(&mut buffer, token_padding)?;
    buffer.push(HandshakeVersion::Version1.id())?;
    buffer.push(PayloadFrame::DeferredPayloadHash as u8)?;
    buffer.extend_from_slice(deferred_payload_hash)?;
    insert_padding(&mut buffer, tag_padding)?;
    noise.write_message_in_place(&mut buffer.as_mut()[1..])?;
    Ok(())
}

fn write_responder_deferred_payload(buffer: &mut impl Buffer, noise: &mut impl NoiseHandshake, transport_params: &[u8], zero_rtt_accepted: bool, driver: &mut impl HandshakeDriver, position: u8) -> Result<(), Error> {
    let mut buffer = MaxLenBuffer::new(buffer, u16::MAX as usize)?;
    buffer.push(HandshakeMessage::DeferredPayload as u8)?;
    buffer.push(HandshakeVersion::Version1.id())?;
    insert_varlen_frame(&mut buffer, PayloadFrame::TransportParameters, transport_params)?;
    if zero_rtt_accepted {
        buffer.push(PayloadFrame::ZeroRttAccepted as u8)?;
    }
    insert_application_payload(&mut buffer, noise, driver, Some(position))?;
    Ok(())
}

fn write_noise(buffer: &mut impl Buffer, noise: &mut impl NoiseHandshake, driver: &mut impl HandshakeDriver, position: u8) -> Result<(), Error> {
    let mut buffer = MaxLenBuffer::new(buffer, u16::MAX as usize)?;
    let (token_padding, tag_padding) = noise.next_message_layout()?;
    buffer.push(HandshakeMessage::Noise as u8)?;
    insert_padding(&mut buffer, token_padding)?;

    let mut noise_wrapper = NoiseHandshakeWrapper::wrap_payload(noise, Some(position), None);
    driver.write_noise_payload(&mut AppendOnlyBuffer::new(&mut buffer), &mut noise_wrapper)?;

    insert_padding(&mut buffer, tag_padding)?;
    noise.write_message_in_place(&mut buffer.as_mut()[1..])?;
    Ok(())
}

fn write_final(buffer: &mut impl Buffer, noise: &mut impl NoiseHandshake, driver: &mut impl HandshakeDriver) -> Result<(), Error> {
    let mut buffer = MaxLenBuffer::new(buffer, u16::MAX as usize)?;
    let mut buffer = AppendOnlyBuffer::new(&mut buffer);
    buffer.push(HandshakeMessage::FinalPayload as u8)?;
    buffer.push(HandshakeVersion::Version1.id())?;
    buffer.push(PayloadFrame::ApplicationPayload as u8)?;
    let mut noise_wrapper = NoiseHandshakeWrapper::wrap_payload(noise, None, None);
    driver.write_final_payload(&mut AppendOnlyBuffer::new(&mut buffer), &mut noise_wrapper)?;
    if buffer.len() == 3 {
        buffer.clear();
        buffer.push(HandshakeMessage::Final as u8)?;
    }
    Ok(())
}

fn insert_varlen_frame(buffer: &mut impl Buffer, frame: PayloadFrame, payload: &[u8]) -> Result<(), Error> {
    buffer.push(frame as u8)?;
    let mut len_buffer = VarLengthPrefixBuffer::new(buffer, payload.len())?;
    len_buffer.extend_from_slice(payload)?;
    Ok(())
}

fn insert_application_payload(buffer: &mut impl Buffer, noise: &mut impl NoiseHandshake, driver: &mut impl HandshakeDriver, position: Option<u8>) -> Result<(), Error> {
    let mut buffer = AppendOnlyBuffer::new(buffer);
    buffer.push(PayloadFrame::ApplicationPayload as u8)?;
    let mut noise_wrapper = NoiseHandshakeWrapper::wrap_payload(noise, position, None);
    driver.write_noise_payload(&mut AppendOnlyBuffer::new(&mut buffer), &mut noise_wrapper)?;
    if buffer.len() == 1 {
        buffer.clear();
    }
    Ok(())
}

fn insert_padding(buffer: &mut impl Buffer, len: usize) -> Result<(), Error> {
    for _ in 0..len {
        buffer.push(0)?;
    }
    Ok(())
}
