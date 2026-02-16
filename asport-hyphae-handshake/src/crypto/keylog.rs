use crate::{crypto::{CryptoBackend, CryptoError, NoiseHandshake, SecretKeySetup, SymmetricKey, TransportRekey}, handshake::HYPHAE_KEY_ASK_LABEL, crypto::noise::x25519::PublicKey};

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct LoggedSecret {
    pub label: SecretLabel,
    pub client_e: Vec<u8>,
    pub secret: Vec<u8>,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[non_exhaustive]
pub enum SecretLabel {
    NoiseProtocol,
    Handshake,
    OneRtt (u64),
}

impl SecretLabel {
    fn next(label: Option<Self>) -> Option<Self> {
        match label {
            None => Some(Self::NoiseProtocol),
            Some(Self::NoiseProtocol) => Some(Self::Handshake),
            Some(Self::Handshake) => Some(Self::OneRtt(0)),
            Some(Self::OneRtt(n)) => Some(Self::OneRtt(n.checked_add(1)?)),
        }
    }
}

pub trait SecretReceiver: Clone {
    fn log_secret(&self, secret: LoggedSecret);

    /// A secret was generated at an invalid position in the handshake
    /// for the selected Noise protocol.
    #[allow(unused_variables)]
    fn invalid_secret(&self, protocol: &str, position: u8, secret: &LoggedSecret) {}
}

pub struct KeyLoggingBackend<R: SecretReceiver, B: CryptoBackend> {
    receiver: R,
    inner: B,
}

impl <R, B> KeyLoggingBackend<R, B>
where
    R: SecretReceiver,
    B: CryptoBackend,
{
    pub fn new(secret_receiver: R, crypto: B) -> Self {
        Self {
            receiver: secret_receiver,
            inner: crypto,
        }
    }
}

impl <R, B> CryptoBackend for KeyLoggingBackend<R, B>
where
    R: SecretReceiver,
    B: CryptoBackend,
{
    type InitialCrypto = B::InitialCrypto;

    type NoiseHandshake = KeyLoggingNoiseHandshake<R, B::NoiseHandshake>;

    type TransportCrypto = B::TransportCrypto;

    type TransportRekey = KeyLoggingTransportRekey<R, B::TransportRekey>;

    fn protocol_supported(&self, noise_protocol: &str) -> bool {
        self.inner.protocol_supported(noise_protocol)
    }

    fn initial_crypto(&self) -> Self::InitialCrypto {
        self.inner.initial_crypto()
    }

    fn new_handshake(&self) -> Result<Self::NoiseHandshake, CryptoError> {
        Ok(KeyLoggingNoiseHandshake::new(self.receiver.clone(), self.inner.new_handshake()?))
    }

    fn transport_crypto(&self, handshake: &Self::NoiseHandshake) -> Result<Self::TransportCrypto, CryptoError> {
        self.inner.transport_crypto(&handshake.inner)
    }

    fn export_1rtt_rekey(&self, handshake: &mut Self::NoiseHandshake, rekey: &mut Self::TransportRekey) -> Result<(), CryptoError> {
        self.inner.export_1rtt_rekey(&mut handshake.inner, &mut rekey.inner)?;

        rekey.last_logged_secret = handshake.last_logged_secret;
        rekey.receiver = Some(handshake.receiver.clone());
        rekey.initiator_ephemeral = handshake.initiator_ephemeral.clone();

        Ok(())
    }
}

pub struct KeyLoggingNoiseHandshake<R: SecretReceiver, X: NoiseHandshake> {
    receiver: R,
    last_logged_secret: Option<SecretLabel>,
    initiator_ephemeral: Vec<u8>,
    noise_protocol: Option<String>,
    position: u8,
    inner: X,
}

impl <R, X> KeyLoggingNoiseHandshake<R, X>
where
    R: SecretReceiver,
    X: NoiseHandshake,
{
    pub fn new(secret_receiver: R, noise_handshake: X) -> Self {
        Self {
            receiver: secret_receiver,
            last_logged_secret: None,
            initiator_ephemeral: vec![0u8; PublicKey::SIZE],
            noise_protocol: None,
            position: 0,
            inner: noise_handshake,
        }
    }

    fn noise_proto(&self) -> &str {
        match self.noise_protocol.as_ref() {
            Some(p) => p.as_str(),
            None => "",
        }
    }
}

impl <R, X> NoiseHandshake for KeyLoggingNoiseHandshake<R, X>
where
    R: SecretReceiver,
    X: NoiseHandshake,
{
    fn initialize<'a> (
        &mut self,
        rng: &mut (impl rand_core::CryptoRng + rand_core::RngCore),
        protocol_name: &str,
        initiator: bool,
        prologue: impl Iterator<Item = &'a[u8]>,
        s: Option<SecretKeySetup>,
        rs: Option<&[u8]>
    ) -> Result<(), CryptoError> {
        self.noise_protocol = Some(protocol_name.into());
        self.inner.initialize(rng, protocol_name, initiator, prologue, s, rs)
    }

    fn write_message_in_place(&mut self, buffer: &mut [u8]) -> Result<(), CryptoError> {
        self.position = self.position.saturating_add(1);
        self.inner.write_message_in_place(buffer)?;
        if self.position == 1 && buffer.len() >= PublicKey::SIZE {
            self.initiator_ephemeral.copy_from_slice(&buffer[0..PublicKey::SIZE]);
        }
        Ok(())
    }

    fn read_message_in_place<'a> (&mut self, buffer: &'a mut [u8]) -> Result<&'a [u8], CryptoError> {
        self.position = self.position.saturating_add(1);
        if self.position == 1 && buffer.len() >= PublicKey::SIZE {
            self.initiator_ephemeral.copy_from_slice(&buffer[0..PublicKey::SIZE]);
        }
        self.inner.read_message_in_place(buffer)
    }

    fn next_message_layout(&self) -> Result<(usize, usize), CryptoError> {
        self.inner.next_message_layout()
    }

    fn is_reset(&self) -> bool {
        self.inner.is_reset()
    }

    fn is_initiator(&self) -> bool {
        self.inner.is_initiator()
    }

    fn is_my_turn(&self) -> bool {
        self.inner.is_my_turn()
    }

    fn is_finished(&self) -> bool {
        self.inner.is_finished()
    }

    fn remote_public(&self) -> Option<&[u8]> {
        self.inner.remote_public()
    }

    fn handshake_hash(&self) -> &[u8] {
        self.inner.handshake_hash()
    }

    fn get_ask(&mut self, label: &[u8], key: &mut SymmetricKey) -> Result<(), CryptoError> {
        self.inner.get_ask(label, key)?;

        if label != HYPHAE_KEY_ASK_LABEL {
            return Ok(());
        }

        if self.last_logged_secret.is_none() {
            // We should have the initiator ephemeral by now, log the stored protocol.
            let protocol = LoggedSecret {
                label: SecretLabel::Handshake,
                client_e: self.initiator_ephemeral.clone(),
                secret: self.noise_protocol.take().unwrap_or_default().into(),
            };
            self.receiver.log_secret(protocol);
            self.last_logged_secret = Some(SecretLabel::NoiseProtocol);
        }

        let Some(label) = SecretLabel::next(self.last_logged_secret) else {
            return Ok(());
        };

        let secret = LoggedSecret {
            label,
            client_e: self.initiator_ephemeral.clone(),
            secret: key.as_ref().to_vec(),
        };

        match label {
            SecretLabel::NoiseProtocol => {}
            SecretLabel::Handshake => {
                if self.position != 2 {
                    self.receiver.invalid_secret(self.noise_proto(), self.position, &secret);
                }
            },
            SecretLabel::OneRtt(_) => {
                if !self.is_finished() {
                    self.receiver.invalid_secret(self.noise_proto(), self.position, &secret);
                }
            },
        }

        self.receiver.log_secret(secret);
        self.last_logged_secret = Some(label);

        Ok(())
    }

    fn export_keying_material(&self, label: &[u8], context: &[u8], output: &mut [u8]) -> Result<(), CryptoError> {
        self.inner.export_keying_material(label, context, output)
    }
}

pub struct KeyLoggingTransportRekey<R: SecretReceiver, T: TransportRekey> {
    receiver: Option<R>,
    last_logged_secret: Option<SecretLabel>,
    initiator_ephemeral: Vec<u8>,
    inner: T,
}

impl <R, T> Default for KeyLoggingTransportRekey<R, T>
where
    R: SecretReceiver,
    T: TransportRekey
{
    fn default() -> Self {
        Self { receiver: None, last_logged_secret: None, initiator_ephemeral: Default::default(), inner: Default::default() }
    }
}


impl <R, T> TransportRekey for KeyLoggingTransportRekey<R, T>
where
    R: SecretReceiver,
    T: TransportRekey
{
    fn next_1rtt_secret(&mut self, level_secret: &mut SymmetricKey) {
        self.inner.next_1rtt_secret(level_secret);

        let Some(label) = SecretLabel::next(self.last_logged_secret) else {
            return;
        };
        let Some(receiver) = self.receiver.as_ref() else {
            return;
        };

        let secret = LoggedSecret {
            label,
            client_e: self.initiator_ephemeral.clone(),
            secret: level_secret.as_ref().to_vec(),
        };

        if !matches!(label, SecretLabel::OneRtt(_)) {
            receiver.invalid_secret("", u8::MAX, &secret);
        }

        receiver.log_secret(secret);
        self.last_logged_secret = Some(label);
    }
}
