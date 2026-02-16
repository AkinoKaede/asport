use std::iter::once;

use rand_core::{CryptoRng, RngCore};
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::{backends::{AeadBackend, HashBackend, HashExt}, CryptoError, SymmetricKey, HYPHAE_AEAD_TAG_LEN};

use self::{patterns::{parse_protocol_name, HandshakeParams, PreMessageTokens, Token}, x25519::{PublicKey, SecretKey, SharedSecret}};

mod ask;
pub mod patterns;
pub(crate) mod x25519;

pub use ask::AskChain;

use super::{NoiseHandshake, SecretKeySetup, TransportRekey as _};

#[derive(Default, Zeroize)]
struct Nonce8 (u8);

impl Nonce8 {
    /// Returns the current nonce or `NoiseError::StateExhausted`.
    fn next(&mut self) -> Result<u64, CryptoError> {
        let n64 = self.0 as u64;
        match self.0.checked_add(1) {
            Some(next_n) => {
                self.0 = next_n;
                Ok(n64)
            },
            None => return Err(CryptoError::StateExhausted),
        }
    }
}

#[derive(Default, Zeroize)]
struct CipherState<A: AeadBackend> {
    aead_impl: A,
    k: Option<SymmetricKey>,
    n: Nonce8,
}

impl<A: AeadBackend> CipherState<A> {
    pub fn initialize_key(&mut self, key: Option<&SymmetricKey>) {
        self.k = key.cloned();
        self.n = Default::default();
    }

    pub fn has_key(&self) -> bool {
        self.k.is_some()
    }

    /// Encrypt `buffer` in-place.
    /// 
    /// `buffer` is a mutable slice containing the plaintext message
    /// and 16 bytes of padding to hold the authentication tag. The
    /// plaintext is encrypted in-place and the tag overwrites the
    /// padding.
    pub fn encrypt_with_ad_in_place(&mut self, ad: &[u8], buffer: &mut [u8]) -> Result<(), CryptoError> {
        let Some(k) = self.k.as_ref() else {
            return Err(CryptoError::InvalidState);
        };
        if buffer.len() < HYPHAE_AEAD_TAG_LEN {
            return Err(CryptoError::InsufficientBuffer);
        }

        self.aead_impl.encrypt_in_place(&k, self.n.next()?, ad, buffer)
    }

    /// Decrypt `buffer` in-place.
    /// 
    /// `buffer` is a mutable slice containing the ciphertext message
    /// and 16 byte authentication tag. The ciphertext is decrypted in-
    /// place and the authentication tag is left in the buffer.
    /// 
    /// Returns a slice containing the decrypted message.
    pub fn decrypt_with_ad_in_place<'a> (&mut self, ad: &[u8], buffer: &'a mut [u8]) -> Result<&'a [u8], CryptoError> {
        let Some(k) = self.k.as_ref() else {
            return Err(CryptoError::InvalidState);
        };
        if buffer.len() < HYPHAE_AEAD_TAG_LEN {
            return Err(CryptoError::InsufficientBuffer);
        }

        self.aead_impl.decrypt_in_place(k, self.n.next()?, ad, buffer)
    }
}

#[derive(Zeroize)]
struct SymmetricState<A: AeadBackend, H: HashBackend> {
    hash_impl: H,
    cipher_state: CipherState<A>,
    ck: H::Hash,
    h: H::Hash,
}

impl <A: AeadBackend, H: HashBackend> Default for SymmetricState<A, H> {
    fn default() -> Self {
        let hash_impl = H::default();
        Self { hash_impl: Default::default(), cipher_state: Default::default(), ck: hash_impl.zeros(), h: hash_impl.zeros() }
    }
}

impl <A: AeadBackend, H: HashBackend> SymmetricState<A, H> {
    pub fn initialize_crypto(&mut self, aead_protocol: &str, hash_protocol: &str) -> Result<(), CryptoError> {
        self.cipher_state = Default::default();
        self.cipher_state.aead_impl.initialize(aead_protocol)?;
        self.hash_impl.initialize(hash_protocol)?;
        Ok(())
    }

    pub fn initialize_symmetric(&mut self, protocol_name: &[u8]) {
        // Note: `cipher_state` is reset in `initialize_crypto`.
        if protocol_name.len() <= self.hash_impl.hash_as_slice(&self.h).len() {
            self.h = self.hash_impl.zeros();
            self.hash_impl.hash_as_mut_slice(&mut self.h)[0..protocol_name.len()].copy_from_slice(protocol_name);
        } else {
            self.hash_impl.hash_into(&mut self.h, false, once(protocol_name));
        }
        self.ck = self.h.clone();
    }

    pub fn mix_hash(&mut self, input: &[u8]) {
        self.mix_hash_multi(once(input));
    }

    pub fn mix_hash_multi<'a> (&mut self, inputs: impl Iterator<Item = &'a[u8]>) {
        self.hash_impl.hash_into(&mut self.h, true, inputs);
    }

    pub fn mix_key(&mut self, input_key_material: &[u8]) {
        let mut ck_next = Zeroizing::new(self.hash_impl.zeros());
        let mut temp_k = Zeroizing::new(SymmetricKey::default());
        self.hash_impl.hkdf(&self.ck, [self.hash_impl.hash_as_mut_slice(&mut ck_next), temp_k.as_mut()], once(input_key_material), b"");

        self.ck = (&*ck_next).clone();
        self.cipher_state.initialize_key(Some(&temp_k));
    }

    pub fn encrypt_and_hash_in_place(&mut self, buffer: &mut [u8]) -> Result<(), CryptoError>{
        if self.cipher_state.has_key() {
            self.cipher_state.encrypt_with_ad_in_place(self.hash_impl.hash_as_slice(&self.h), buffer)?;
        }
        self.mix_hash(buffer);
        Ok(())
    }

    pub fn decrypt_and_hash_in_place<'a> (&mut self, buffer: &'a mut [u8]) -> Result<&'a [u8], CryptoError> {
        let ad = self.h.clone();
        self.mix_hash(buffer);
        if self.cipher_state.has_key() {
            self.cipher_state.decrypt_with_ad_in_place(self.hash_impl.hash_as_slice(&ad), buffer)
        } else {
            Ok(buffer)
        }
    }

    pub fn get_handshake_hash(&self) -> &[u8] {
        self.hash_impl.hash_as_slice(&self.h)
    }

    pub fn has_key(&self) -> bool {
        self.cipher_state.has_key()
    }
}

impl <A: AeadBackend, H: HashBackend> Drop for SymmetricState<A, H> {
    fn drop(&mut self) {
        self.ck.zeroize();
    }
}

#[derive(Default, Zeroize)]
struct HandshakeKeys {
    e_secret: SecretKey,
    s_secret: SecretKey,
    re: PublicKey,
    rs: PublicKey,
    state: u8,
}

impl HandshakeKeys {
    const STATE_HAS_E: u8 = 0x01;
    const STATE_HAS_S: u8 = 0x02;
    const STATE_HAS_RE: u8 = 0x04;
    const STATE_HAS_RS: u8 = 0x08;
    const STATE_DH_E_RE: u8 = 0x10;
    const STATE_DH_E_RS: u8 = 0x20;
    const STATE_DH_S_RE: u8 = 0x40;
    const STATE_DH_S_RS: u8 = 0x80;

    pub fn static_public(&self) -> Result<PublicKey, CryptoError> {
        self.validity_check(Self::STATE_HAS_S, 0)?;
        Ok(self.s_secret.public())
    }

    pub fn ephemeral_public(&self) -> Result<PublicKey, CryptoError> {
        self.validity_check(Self::STATE_HAS_E, 0)?;
        Ok(self.e_secret.public())
    }
    
    pub fn remote_static_public(&self) -> Result<&PublicKey, CryptoError> {
        self.validity_check(Self::STATE_HAS_RS, 0)?;
        Ok(&self.rs)
    }

    pub fn init_ephemeral_rng(&mut self, rng: &mut (impl CryptoRng + RngCore)) -> Result<(), CryptoError> {
        self.validity_set(0, Self::STATE_HAS_E)?;
        self.e_secret = SecretKey::new_from_rng(rng);
        Ok(())
    }

    pub fn set_local_static(&mut self, s_secret: &SecretKey) -> Result<(), CryptoError> {
        self.validity_set(0, Self::STATE_HAS_S)?;
        self.s_secret = s_secret.clone_private();
        Ok(())
    }

    pub fn set_remote_static(&mut self, rs_public: &[u8]) -> Result<(), CryptoError> {
        self.validity_set(0, Self::STATE_HAS_RS)?;
        self.rs = rs_public.try_into()?;
        Ok(())
    }

    pub fn set_remote_ephemeral(&mut self, re_public: &[u8]) -> Result<(), CryptoError> {
        self.validity_set(0, Self::STATE_HAS_RE)?;
        self.re = re_public.try_into()?;
        Ok(())
    }

    pub fn dh_ee(&mut self) -> Result<SharedSecret, CryptoError> {
        self.validity_set(Self::STATE_HAS_E | Self::STATE_HAS_RE, Self::STATE_DH_E_RE)?;
        Ok(self.e_secret.diffie_hellman(&self.re))
    }

    pub fn dh_es(&mut self) -> Result<SharedSecret, CryptoError> {
        self.validity_set(Self::STATE_HAS_E | Self::STATE_HAS_RS, Self::STATE_DH_E_RS)?;
        Ok(self.e_secret.diffie_hellman(&self.rs))
    }

    pub fn dh_se(&mut self) -> Result<SharedSecret, CryptoError> {
        self.validity_set(Self::STATE_HAS_S | Self::STATE_HAS_RE, Self::STATE_DH_S_RE)?;
        Ok(self.s_secret.diffie_hellman(&self.re))
    }

    pub fn dh_ss(&mut self) -> Result<SharedSecret, CryptoError> {
        self.validity_set(Self::STATE_HAS_S | Self::STATE_HAS_RS, Self::STATE_DH_S_RS)?;
        Ok(self.s_secret.diffie_hellman(&self.rs))
    }

    fn validity_check(&self, must_have: u8, must_set: u8) -> Result<(), CryptoError> {
        if self.state & must_have != must_have || self.state & must_set != 0 {
            return Err(CryptoError::Internal)
        } else {
            Ok(())
        }
    }

    fn validity_set(&mut self, must_have: u8, must_set: u8) -> Result<(), CryptoError> {
        self.validity_check(must_have, must_set)?;
        self.state |= must_set;
        Ok(())
    }
}

#[derive(Zeroize)]
pub struct HandshakeState<A: AeadBackend, H: HashBackend> {
    #[zeroize(skip)]
    handshake: Option<HandshakeParams>,
    symmetric_state: SymmetricState<A, H>,
    keys: HandshakeKeys,
    step: u8,
    level_secret_ask_count: u8,
    initiator: bool,
}

impl<A: AeadBackend, H: HashBackend> Default for HandshakeState<A, H> {
    fn default() -> Self {
        Self { handshake: Default::default(), symmetric_state: Default::default(), keys: Default::default(), step: Default::default(), level_secret_ask_count: 0, initiator: Default::default() }
    }
}

impl<A: AeadBackend, H: HashBackend> HandshakeState<A, H> {
    pub fn parse_protocol(protocol_name: &str) -> Result<(HandshakeParams, &str, &str), CryptoError> {
        let (handshake, diffie_hellman, aead, hash) = parse_protocol_name(protocol_name)?;
        if diffie_hellman != "25519" {
            return Err(CryptoError::UnsupportedProtocol);
        }

        A::default().initialize(aead)?;
        H::default().initialize(hash)?;

        if handshake.has_modifier_hfs() || handshake.has_modifier_psk(None) {
            return Err(CryptoError::UnsupportedProtocol); 
        }

        Ok((handshake, aead, hash))
    }

    pub fn initialize<'a> (&mut self, rng: &mut (impl CryptoRng + RngCore), protocol_name: &str, initiator: bool, prologue: impl Iterator<Item = &'a[u8]>, s: Option<&SecretKey>, rs: Option<&PublicKey>) -> Result<(), CryptoError> {
        if !self.is_reset() {
            return Err(CryptoError::InvalidState);
        }

        let (handshake, aead, hash) = Self::parse_protocol(protocol_name)?;
        self.symmetric_state.initialize_crypto(aead, hash)?;

        self.handshake = Some(handshake);
        self.initiator = initiator;
        self.keys.init_ephemeral_rng(rng)?;
        if let Some(s) = s {
            self.keys.set_local_static(s)?;
        }
        if let Some(rs) = rs {
            self.keys.set_remote_static(rs.as_ref())?;
        }
        self.symmetric_state.initialize_symmetric(protocol_name.as_bytes());
        self.symmetric_state.mix_hash_multi(prologue);

        let handshake_desc = handshake.pattern().handshake_desc();
        match (handshake_desc.pre_message_init, initiator) {
            (PreMessageTokens::Empty, _) => {},
            (PreMessageTokens::S, true) => self.symmetric_state.mix_hash(self.keys.static_public()?.as_ref()),
            (PreMessageTokens::S, false) => self.symmetric_state.mix_hash(self.keys.rs.as_ref()),
        }
        match (handshake_desc.pre_message_resp, initiator) {
            (PreMessageTokens::Empty, _) => {},
            (PreMessageTokens::S, true) => self.symmetric_state.mix_hash(self.keys.rs.as_ref()),
            (PreMessageTokens::S, false) => self.symmetric_state.mix_hash(self.keys.static_public()?.as_ref()),
        }

        self.step = 0;

        Ok(())
    }

    /// Returns true if this handshake state is reset and ready for a
    /// call to `initialize(...)`.
    pub fn is_reset(&self) -> bool {
        self.handshake.is_none()
    }

    /// Returns true if handshake state is for an initiator.
    /// 
    /// Returns false before calling `initialize(...)`.
    pub fn is_initiator(&self) -> bool {
        self.initiator
    }

    /// Returns true if the handshake is complete.
    pub fn is_complete(&self) -> bool {
        self.handshake
            .as_ref()
            .map(|h| self.step as usize >= h.message_count())
            .unwrap_or(false)
    }

    /// Returns true if this handshake state must write the next message.
    pub fn is_my_turn(&self) -> bool {
        if self.is_reset() || self.is_complete() {
            return false;
        }

        let phase = if self.is_initiator() {
            0
        } else {
            1
        };
        
        self.step % 2 == phase
    }

    pub fn aead_backend(&self) -> Result<A, CryptoError> {
        if self.is_reset() {
            Err(CryptoError::InvalidState)
        } else {
            Ok(self.symmetric_state.cipher_state.aead_impl.clone())
        }
    }

    pub fn hash_backend(&self) -> Result<H, CryptoError> {
        if self.is_reset() {
            Err(CryptoError::InvalidState)
        } else {
            Ok(self.symmetric_state.hash_impl.clone())
        }
    }

    pub fn write_message_in_place(&mut self, buffer: &mut [u8]) -> Result<(), CryptoError> {
        if !self.is_my_turn() {
            return Err(CryptoError::InvalidState);
        }
        if buffer.len() < self.next_message_length() {
            return Err(CryptoError::InsufficientBuffer);
        }

        let mut cursor = 0;

        for token in self.next_message_tokens()? {
            match token {
                Token::E => {
                    buffer[cursor..cursor+PublicKey::SIZE].copy_from_slice(self.keys.ephemeral_public()?.as_ref());
                    self.symmetric_state.mix_hash(&buffer[cursor..cursor+PublicKey::SIZE]);
                    cursor += PublicKey::SIZE;
                },
                Token::S => {
                    buffer[cursor..cursor+PublicKey::SIZE].copy_from_slice(self.keys.static_public()?.as_ref());
                    let s_size = if self.symmetric_state.has_key() {
                        PublicKey::SIZE + 16
                    } else {
                        PublicKey::SIZE
                    };
                    self.symmetric_state.encrypt_and_hash_in_place(&mut buffer[cursor..cursor+s_size])?;
                    cursor += s_size;
                },
                Token::DhEE => {
                    self.symmetric_state.mix_key(self.keys.dh_ee()?.as_ref());
                },
                Token::DhES =>  {
                    match self.initiator {
                        true => self.symmetric_state.mix_key(self.keys.dh_es()?.as_ref()),
                        false => self.symmetric_state.mix_key(self.keys.dh_se()?.as_ref()),
                    }
                },
                Token::DhSE => {
                    match self.initiator {
                        true => self.symmetric_state.mix_key(self.keys.dh_se()?.as_ref()),
                        false => self.symmetric_state.mix_key(self.keys.dh_es()?.as_ref()),
                    }
                },
                Token::DhSS =>  {
                    self.symmetric_state.mix_key(self.keys.dh_ss()?.as_ref());
                },
                Token::Psk(_) => todo!(),
            }
        }

        self.symmetric_state.encrypt_and_hash_in_place(&mut buffer[cursor..])?;
        self.step += 1;
        self.level_secret_ask_count = 0;

        Ok(())
    }

    #[cfg(any(test, feature = "alloc"))]
    pub fn write_message_vec(&mut self, payload: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let (token_bytes, payload_tag_bytes) = self.next_message_layout();
        // todo, check payload max len
        let mut message = vec![0u8; token_bytes + payload.len() + payload_tag_bytes];
        message[token_bytes..token_bytes + payload.len()].copy_from_slice(payload);
        self.write_message_in_place(&mut message).map_err(|e| { message.zeroize(); e })?;
        Ok(message)
    }

    pub fn read_message_in_place<'a> (&mut self, buffer: &'a mut [u8]) -> Result<&'a [u8], CryptoError> {
        if self.is_my_turn() {
            return Err(CryptoError::InvalidState);
        }
        if buffer.len() < self.next_message_length() {
            return Err(CryptoError::DecryptionFailed);
        }

        let mut cursor = 0;

        for token in self.next_message_tokens()? {
            match token {
                Token::E => {
                    self.symmetric_state.mix_hash(&buffer[cursor..cursor+PublicKey::SIZE]);
                    self.keys.set_remote_ephemeral(&buffer[cursor..cursor+PublicKey::SIZE])?;
                    cursor += PublicKey::SIZE;
                },
                Token::S => {
                    let s_size = if self.symmetric_state.has_key() {
                        PublicKey::SIZE + 16
                    } else {
                        PublicKey::SIZE
                    };
                    let rs = self.symmetric_state.decrypt_and_hash_in_place(&mut buffer[cursor..cursor+s_size])?;
                    self.keys.set_remote_static(rs)?;
                    cursor += s_size;
                },
                Token::DhEE => {
                    self.symmetric_state.mix_key(self.keys.dh_ee()?.as_ref());
                },
                Token::DhES =>  {
                    match self.initiator {
                        true => self.symmetric_state.mix_key(self.keys.dh_es()?.as_ref()),
                        false => self.symmetric_state.mix_key(self.keys.dh_se()?.as_ref()),
                    }
                },
                Token::DhSE => {
                    match self.initiator {
                        true => self.symmetric_state.mix_key(self.keys.dh_se()?.as_ref()),
                        false => self.symmetric_state.mix_key(self.keys.dh_es()?.as_ref()),
                    }
                },
                Token::DhSS =>  {
                    self.symmetric_state.mix_key(self.keys.dh_ss()?.as_ref());
                },
                Token::Psk(_) => todo!(),
            }
        }

        let payload = self.symmetric_state.decrypt_and_hash_in_place(&mut buffer[cursor..])?;
        self.step += 1;
        self.level_secret_ask_count = 0;

        Ok(payload)
    }

    #[cfg(any(test, feature = "alloc"))]
    pub fn read_message_vec(&mut self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut buffer = Zeroizing::new(message.to_vec());
        Ok(self.read_message_in_place(&mut buffer)?.to_vec())
    }

    /// Returns the current handshake hash as of the latest processed message.
    pub fn current_handshake_hash(&self) -> &[u8] {
        self.symmetric_state.get_handshake_hash()
    }

    /// Returns the final handshake hash, or `None` if the handshake
    /// is not yet finished.
    pub fn final_handshake_hash(&self) -> Option<&[u8]> {
        self.is_complete().then(|| self.current_handshake_hash())
    }

    /// Returns the remote peer's static (public) key if it is known.
    /// 
    /// Warning, if the handshake is not finished, this key may not be
    /// authenticated yet.
    pub fn remote_static(&self) -> Option<&[u8]> {
        self.keys.remote_static_public().ok().map(PublicKey::as_ref)
    }

    pub fn reset(&mut self) {
        self.zeroize();
        *self = Default::default();
    }

    /// Export keying material for application use
    /// 
    /// This derives key material from the final handshake state using HKDF.
    /// The derivation uses the chaining key (ck) as the PRK and combines
    /// the handshake hash, custom label, and context as the info parameter.
    pub fn export_keying_material(&self, label: &[u8], context: &[u8], output: &mut [u8]) -> Result<(), CryptoError> {
        if !self.is_complete() {
            return Err(CryptoError::InvalidState);
        }
        
        // Use HKDF-Expand with the chaining key as PRK
        // Info = handshake_hash || label_length || label || context_length || context || "hyphae-export"
        let handshake_hash = self.current_handshake_hash();
        
        // Build the info parameter
        let mut info = Vec::new();
        info.extend_from_slice(&(handshake_hash.len() as u16).to_be_bytes());
        info.extend_from_slice(handshake_hash);
        info.extend_from_slice(&(label.len() as u16).to_be_bytes());
        info.extend_from_slice(label);
        info.extend_from_slice(&(context.len() as u16).to_be_bytes());
        info.extend_from_slice(context);
        info.extend_from_slice(b"hyphae-export");
        
        // For outputs larger than hash size, we need to use HKDF-Expand properly
        // Split the output into hash-sized chunks
        let hash_size = self.symmetric_state.hash_impl.hash_as_slice(&self.symmetric_state.ck).len();
        
        for (i, chunk) in output.chunks_mut(hash_size).enumerate() {
            let mut full_info = info.clone();
            full_info.push((i + 1) as u8);  // HKDF-Expand counter
            
            if chunk.len() == hash_size {
                // Full hash-sized chunk
                let mut temp_hash = self.symmetric_state.hash_impl.zeros();
                self.symmetric_state.hash_impl.hkdf(
                    &self.symmetric_state.ck,
                    [self.symmetric_state.hash_impl.hash_as_mut_slice(&mut temp_hash)],
                    std::iter::once(full_info.as_slice()),
                    b""
                );
                chunk.copy_from_slice(self.symmetric_state.hash_impl.hash_as_slice(&temp_hash));
            } else {
                // Partial chunk at the end
                let mut temp_hash = self.symmetric_state.hash_impl.zeros();
                self.symmetric_state.hash_impl.hkdf(
                    &self.symmetric_state.ck,
                    [self.symmetric_state.hash_impl.hash_as_mut_slice(&mut temp_hash)],
                    std::iter::once(full_info.as_slice()),
                    b""
                );
                let temp_slice = self.symmetric_state.hash_impl.hash_as_slice(&temp_hash);
                chunk.copy_from_slice(&temp_slice[..chunk.len()]);
            }
        }
        
        Ok(())
    }

    pub fn export_ask_into(&mut self, ask: &mut AskChain<H>, label: &[u8]) -> Result<(), CryptoError> {
        if self.handshake.is_none() || self.level_secret_ask_count == u8::MAX {
            return Err(CryptoError::InvalidState);
        }
        if label != crate::handshake::HYPHAE_KEY_ASK_LABEL {
            return Err(super::CryptoError::Internal);
        }

        ask.hash_impl = self.symmetric_state.hash_impl.clone();
        let ask_ck = ask.ask_ck.insert(ask.hash_impl.zeros());

        ask.hash_impl.hkdf(
            &self.symmetric_state.ck,
            [ask.hash_impl.hash_as_mut_slice(ask_ck)], 
            [ask.hash_impl.hash_as_slice(&self.symmetric_state.h), label],
            b"ask");
        
        for _ in 0..self.level_secret_ask_count {
            let mut skip_key = SymmetricKey::default();
            ask.get_ask_into(&mut skip_key)?;
        }

        self.level_secret_ask_count = u8::MAX;

        Ok(())
    }

    fn get_ask(&mut self, label: &[u8], key: &mut SymmetricKey) -> Result<(), CryptoError> {
        if self.handshake.is_none() {
            return Err(CryptoError::InvalidState);
        }
        if label != crate::handshake::HYPHAE_KEY_ASK_LABEL {
            return Err(super::CryptoError::Internal);
        }
        let next_level_secret_ask_count = match self.level_secret_ask_count.checked_add(1) {
            Some(n) => n,
            None => return Err(CryptoError::InvalidState),
        };
        let mut ask = AskChain::default();
        self.export_ask_into(&mut ask, label)?;
        self.level_secret_ask_count = next_level_secret_ask_count;
        
        ask.next_1rtt_secret(key);
        Ok(())
    }

    fn next_message_tokens(&self) -> Result<impl Iterator<Item = Token>, CryptoError> {
        self.handshake
            .as_ref()
            .ok_or(CryptoError::InvalidState)
            .and_then(|h| h.message_token_iter(self.step as usize))
    }

    /// Returns number of bytes before and after the payload for the
    /// next handshake message.
    pub fn next_message_layout(&self) -> (usize, usize) {
        let mut has_key = self.symmetric_state.has_key();
        let mut token_bytes = 0;
        let Some(pattern) = self.handshake else {
            return (0, 0);
        };
        let Ok(token_iter) = self.next_message_tokens() else {
            return (0, 0);
        };
        for token in token_iter {
            match token {
                Token::E => {
                    token_bytes += PublicKey::SIZE;
                    if pattern.has_modifier_psk(None) {
                        has_key = true;
                    }
                },
                Token::S => {
                    token_bytes += PublicKey::SIZE;
                    if has_key {
                        token_bytes += 16;
                    }
                },
                Token::DhEE |
                Token::DhES |
                Token::DhSE |
                Token::DhSS => has_key = true,
                Token::Psk(_) => has_key = true,
            }
        }
        let payload_tag_bytes = if has_key {
            16
        } else {
            0
        };
        (token_bytes, payload_tag_bytes)
    }

    /// Returns the length of the next handshake message excluding the
    /// payload.
    fn next_message_length(&self) -> usize {
        let (token_bytes, payload_tag_bytes) = self.next_message_layout();
        token_bytes + payload_tag_bytes
    }
}

impl <A: AeadBackend, H: HashBackend> NoiseHandshake for HandshakeState<A, H> {
    fn initialize<'a> (&mut self, rng: &mut (impl rand_core::CryptoRng + rand_core::RngCore), protocol_name: &str, initiator: bool, prologue: impl Iterator<Item = &'a[u8]>, s: Option<super::SecretKeySetup>, rs: Option<&[u8]>) -> Result<(), super::CryptoError> {
        let s = match s {
            None => None,
            Some(SecretKeySetup::BackendRemote) => return Err(CryptoError::UnsupportedSecretKey),
            Some(SecretKeySetup::Local(key)) => Some(SecretKey::try_from(key)?),
        };
        let rs = match rs {
            Some(rs) => Some(PublicKey::try_from(rs)?),
            None => None,
        };
        self.initialize(rng, protocol_name, initiator, prologue, s.as_ref(), rs.as_ref())
    }

    fn write_message_in_place(&mut self, buffer: &mut [u8]) -> Result<(), super::CryptoError> {
        self.write_message_in_place(buffer)
    }

    fn read_message_in_place<'a> (&mut self, buffer: &'a mut [u8]) -> Result<&'a [u8], super::CryptoError> {
        self.read_message_in_place(buffer)
    }

    fn next_message_layout(&self) -> Result<(usize, usize), super::CryptoError> {
        match self.next_message_layout() {
            (0, 0) => Err(CryptoError::InvalidState),
            layout => Ok(layout),
        }
    }

    fn is_reset(&self) -> bool {
        self.is_reset()
    }

    fn is_initiator(&self) -> bool {
        self.is_initiator()
    }

    fn is_my_turn(&self) -> bool {
        self.is_my_turn()
    }

    fn is_finished(&self) -> bool {
        self.is_complete()
    }

    fn handshake_hash(&self) -> &[u8] {
        self.current_handshake_hash()
    }

    fn remote_public(&self) -> Option<&[u8]> {
        self.remote_static()
    }

    fn get_ask(&mut self, label: &[u8], key: &mut SymmetricKey) -> Result<(), CryptoError> {
        self.get_ask(label, key)
    }

    fn export_keying_material(&self, label: &[u8], context: &[u8], output: &mut [u8]) -> Result<(), CryptoError> {
        self.export_keying_material(label, context, output)
    }
}

#[cfg(test)]
mod tests {
    use std::ops::Range;

    use rand_core::OsRng;

    use crate::{crypto::{backends::rustcrypto::{AnyAead, AnyHash, Blake2b, Blake2s, ChaChaPoly, RustCryptoBackend}, noise::patterns::{PreMessageTokens, ALL_HANDSHAKE_PATTERNS}, CryptoBackend}, handshake::HYPHAE_KEY_ASK_LABEL};

    use super::*;

    #[test]
    fn cipher_state_roundtrip() {
        let key = SymmetricKey::default();
        let mut cipher_state = CipherState::<ChaChaPoly>::default();
        cipher_state.initialize_key(Some(&key));
        let ad = b"1234";
        let buffer = vec![1u8; 32];
        let mut enc_buffer = buffer.clone();
        cipher_state.encrypt_with_ad_in_place(ad, &mut enc_buffer).unwrap();

        cipher_state.initialize_key(Some(&key));
        cipher_state.decrypt_with_ad_in_place(ad, &mut enc_buffer).unwrap();
        assert_eq!(buffer[0..16], enc_buffer[0..16]);

        let buffer = vec![0u8; 16];
        let mut enc_buffer = buffer.clone();
        cipher_state.initialize_key(Some(&key));
        cipher_state.encrypt_with_ad_in_place(ad, &mut enc_buffer).unwrap();

        cipher_state.initialize_key(Some(&key));
        cipher_state.decrypt_with_ad_in_place(ad, &mut enc_buffer).unwrap();
    }

    #[test]
    fn noise_round_trip_with_snow() {
        let mut protocols = Vec::new();
        for handshake in ALL_HANDSHAKE_PATTERNS {
            protocols.push(format!("Noise_{}_25519_ChaChaPoly_BLAKE2s", handshake.name()));
        }

        for protocol_name in protocols.iter() {
            compare_handshake_with_snow::<ChaChaPoly, Blake2s>(protocol_name, true, 0..0);
            compare_handshake_with_snow::<ChaChaPoly, Blake2s>(protocol_name, false, 0..0);
            compare_handshake_with_snow::<ChaChaPoly, Blake2s>(protocol_name, true, 1..1024);
            compare_handshake_with_snow::<ChaChaPoly, Blake2s>(protocol_name, false, 1..1024);
        }

        protocols.clear();
        for handshake in ALL_HANDSHAKE_PATTERNS {
            protocols.push(format!("Noise_{}_25519_ChaChaPoly_BLAKE2b", handshake.name()));
        }

        for protocol_name in protocols.iter() {
            compare_handshake_with_snow::<ChaChaPoly, Blake2b>(protocol_name, true, 0..0);
            compare_handshake_with_snow::<ChaChaPoly, Blake2b>(protocol_name, false, 0..0);
            compare_handshake_with_snow::<ChaChaPoly, Blake2b>(protocol_name, true, 1..1024);
            compare_handshake_with_snow::<ChaChaPoly, Blake2b>(protocol_name, false, 1..1024);
        }

        protocols.clear();
        for handshake in ALL_HANDSHAKE_PATTERNS {
            protocols.push(format!("Noise_{}_25519_ChaChaPoly_BLAKE2s", handshake.name()));
            protocols.push(format!("Noise_{}_25519_ChaChaPoly_BLAKE2b", handshake.name()));
            protocols.push(format!("Noise_{}_25519_ChaChaPoly_SHA256", handshake.name()));
            protocols.push(format!("Noise_{}_25519_ChaChaPoly_SHA512", handshake.name()));
            protocols.push(format!("Noise_{}_25519_AESGCM_BLAKE2s", handshake.name()));
            protocols.push(format!("Noise_{}_25519_AESGCM_BLAKE2b", handshake.name()));
            protocols.push(format!("Noise_{}_25519_AESGCM_SHA256", handshake.name()));
            protocols.push(format!("Noise_{}_25519_AESGCM_SHA512", handshake.name()));
        }

        for protocol_name in protocols.iter() {
            compare_handshake_with_snow::<AnyAead, AnyHash>(protocol_name, true, 0..0);
            compare_handshake_with_snow::<AnyAead, AnyHash>(protocol_name, false, 0..0);
            compare_handshake_with_snow::<AnyAead, AnyHash>(protocol_name, true, 1..1024);
            compare_handshake_with_snow::<AnyAead, AnyHash>(protocol_name, false, 1..1024);
        }
    }

    #[test]
    fn noise_round_trip() {
        let mut protocols = Vec::new();
        for handshake in ALL_HANDSHAKE_PATTERNS {
            protocols.push(format!("Noise_{}_25519_ChaChaPoly_BLAKE2s", handshake.name()));
        }

        for protocol_name in protocols.iter() {
            handshake_round_trip::<ChaChaPoly, Blake2s>(protocol_name, 0..0);
            handshake_round_trip::<ChaChaPoly, Blake2s>(protocol_name, 1..1024);
        }

        protocols.clear();
        for handshake in ALL_HANDSHAKE_PATTERNS {
            protocols.push(format!("Noise_{}_25519_ChaChaPoly_BLAKE2b", handshake.name()));
        }

        for protocol_name in protocols.iter() {
            handshake_round_trip::<ChaChaPoly, Blake2b>(protocol_name, 0..0);
            handshake_round_trip::<ChaChaPoly, Blake2b>(protocol_name, 1..1024);
        }
        
        protocols.clear();
        for handshake in ALL_HANDSHAKE_PATTERNS {
            protocols.push(format!("Noise_{}_25519_ChaChaPoly_BLAKE2s", handshake.name()));
            protocols.push(format!("Noise_{}_25519_ChaChaPoly_BLAKE2b", handshake.name()));
            protocols.push(format!("Noise_{}_25519_ChaChaPoly_SHA256", handshake.name()));
            protocols.push(format!("Noise_{}_25519_ChaChaPoly_SHA512", handshake.name()));
            protocols.push(format!("Noise_{}_25519_AESGCM_BLAKE2s", handshake.name()));
            protocols.push(format!("Noise_{}_25519_AESGCM_BLAKE2b", handshake.name()));
            protocols.push(format!("Noise_{}_25519_AESGCM_SHA256", handshake.name()));
            protocols.push(format!("Noise_{}_25519_AESGCM_SHA512", handshake.name()));
        }

        for protocol_name in protocols.iter() {
            assert!(RustCryptoBackend.protocol_supported(&protocol_name));
            handshake_round_trip::<AnyAead, AnyHash>(protocol_name, 0..0);
            handshake_round_trip::<AnyAead, AnyHash>(protocol_name, 1..1024);
        }
    }

    #[test]
    fn handshake_dh_validity() {
        let re_secret = SecretKey::new_from_rng(&mut OsRng);
        let re_public = re_secret.public();

        let mut handshake_keys = HandshakeKeys::default();
        handshake_keys.init_ephemeral_rng(&mut OsRng).unwrap();
        handshake_keys.set_remote_ephemeral(re_public.as_ref()).unwrap();

        let e_public = handshake_keys.ephemeral_public().unwrap();
        let ee = handshake_keys.dh_ee().unwrap();
        let r_ee = re_secret.diffie_hellman(&e_public);
        assert_eq!(ee.as_ref(), r_ee.as_ref());
    }

    fn generate_random_payload(payload_size_range: &Range<usize>) -> Vec<u8> {
        let len = 
            (OsRng.next_u64()
            .checked_rem(payload_size_range.len() as u64)
            .unwrap_or_default() as usize)
            + payload_size_range.start;

        let mut payload = vec![0u8; len];
        OsRng.fill_bytes(&mut payload);
        payload
    }

    fn handshake_round_trip<A: AeadBackend, H: HashBackend> (protocol_name: &str, payload_size_range: Range<usize>) {
        let handshake_info = format!("({protocol_name} {payload_size_range:?})");

        let (handshake_params, _, _, _) = parse_protocol_name(protocol_name).unwrap();

        let needs_static_secret = handshake_params.pattern().is_authenticating();
        let key_init_static_secret = needs_static_secret.0.then(|| SecretKey::new_from_rng(&mut OsRng));
        let key_resp_static_secret = needs_static_secret.1.then(|| SecretKey::new_from_rng(&mut OsRng));
        let key_init_static_public = key_init_static_secret.as_ref().map(SecretKey::public);
        let key_resp_static_public = key_resp_static_secret.as_ref().map(SecretKey::public);

        let handshake_desc = handshake_params.pattern().handshake_desc();
        let init_rs = matches!(handshake_desc.pre_message_resp, PreMessageTokens::S).then_some(()).and(key_resp_static_public.clone());
        let resp_rs = matches!(handshake_desc.pre_message_init, PreMessageTokens::S).then_some(()).and( key_init_static_public.clone());

        let mut handshake_i: HandshakeState<A, H> = HandshakeState::default();
        let mut handshake_r: HandshakeState<A, H>  = HandshakeState::default();
        assert!(handshake_i.is_reset());
        assert!(handshake_r.is_reset());
        
        let prologue = generate_random_payload(&payload_size_range);
        handshake_i.initialize(&mut OsRng, protocol_name, true, once(prologue.as_ref()), key_init_static_secret.as_ref(), init_rs.as_ref()).unwrap();
        handshake_r.initialize(&mut OsRng, protocol_name, false, once(prologue.as_ref()), key_resp_static_secret.as_ref(), resp_rs.as_ref()).unwrap();

        assert_eq!(handshake_i.current_handshake_hash(), handshake_r.current_handshake_hash(), "handshake hash diverged at premessage {handshake_info}");

        assert!(handshake_i.is_initiator());
        assert!(!handshake_r.is_initiator());

        let mut step = 0u32;
        while !handshake_i.is_complete() {
            let payload = generate_random_payload(&payload_size_range);

            assert!(!handshake_r.is_complete());
            assert_ne!(handshake_i.is_my_turn(), handshake_r.is_my_turn());

            let (handshake_write, handshake_read) = match handshake_i.is_my_turn() {
                true => (&mut handshake_i, &mut handshake_r),
                false => (&mut handshake_r, &mut handshake_i),
            };

            let message = handshake_write.write_message_vec(&payload).unwrap();
            let res = handshake_read.read_message_vec(&message);

            assert_eq!(handshake_i.current_handshake_hash(), handshake_r.current_handshake_hash(), "handshake hash diverged at step {step} {handshake_info}");
            assert_eq!(payload, res.unwrap());

            let ask_label = HYPHAE_KEY_ASK_LABEL;
            let mut ask_i = AskChain::default();
            let mut ask_r: AskChain<_> = AskChain::default();
            handshake_i.export_ask_into(&mut ask_i, ask_label).unwrap();
            handshake_r.export_ask_into(&mut ask_r, ask_label).unwrap();
            let mut ask_key_i = SymmetricKey::default();
            let mut ask_key_r = SymmetricKey::default();
            ask_i.get_ask_into(&mut ask_key_i).unwrap();
            ask_r.get_ask_into(&mut ask_key_r).unwrap();
            assert_eq!(ask_key_i.as_ref(), ask_key_r.as_ref());

            step += 1;
        }

        assert!(handshake_r.is_complete());
        assert_eq!(handshake_i.remote_static(), key_resp_static_public.as_ref().map(PublicKey::as_ref));
        assert_eq!(handshake_r.remote_static(), key_init_static_public.as_ref().map(PublicKey::as_ref));
    }

    fn compare_handshake_with_snow<A: AeadBackend, H: HashBackend> (protocol_name: &str, initiator: bool, payload_size_range: Range<usize>) {
        let handshake_info = format!("({protocol_name} {initiator} {payload_size_range:?})");

        let (handshake_params, _, _, _) = parse_protocol_name(protocol_name).unwrap();

        let (init_auth, resp_auth) = handshake_params.pattern().is_authenticating();
        let (handshake_auth, snow_auth) = match initiator {
            true => (init_auth, resp_auth),
            false => (resp_auth, init_auth),
        };
        let handshake_static_secret =
            handshake_auth.then(|| SecretKey::new_from_rng(&mut OsRng));
        let snow_static_secret =
            snow_auth.then(|| SecretKey::new_from_rng(&mut OsRng));
        
        let handshake_desc = handshake_params.pattern().handshake_desc();
        let (handshake_premessages, snow_premessages) = match initiator {
            true => (handshake_desc.pre_message_init, handshake_desc.pre_message_resp),
            false => (handshake_desc.pre_message_resp, handshake_desc.pre_message_init),
        };
        let handshake_rs = matches!(snow_premessages, PreMessageTokens::S).then(|| snow_static_secret.as_ref().unwrap().public());
        let snow_rs = matches!(handshake_premessages, PreMessageTokens::S).then(|| handshake_static_secret.as_ref().unwrap().public());

        let prologue = generate_random_payload(&payload_size_range);

        let mut handshake: HandshakeState<A, H> = HandshakeState::default();
        assert!(handshake.is_reset());
        handshake.initialize(&mut OsRng, protocol_name, initiator, once(prologue.as_ref()), handshake_static_secret.as_ref(), handshake_rs.as_ref()).unwrap();

        let mut builder_snow = snow::Builder::new(protocol_name.parse().unwrap()).prologue(&prologue);
        if let Some(s) = &snow_static_secret {
            builder_snow = builder_snow.local_private_key(s.as_bytes());
        }if let Some(rs) = &snow_rs {
            builder_snow = builder_snow.remote_public_key(rs.as_ref());
        }
        let mut handshake_snow = match initiator {
            true => builder_snow.build_responder().unwrap(),
            false => builder_snow.build_initiator().unwrap(),
        };

        assert_eq!(handshake.current_handshake_hash(), handshake_snow.get_handshake_hash(), "handshake hash diverged at premessage {handshake_info}");
        assert_eq!(handshake.is_initiator(), initiator);
        assert_ne!(handshake_snow.is_initiator(), initiator);

        let mut step = 0u32;
        while !handshake.is_complete() {
            let payload = generate_random_payload(&payload_size_range);

            assert!(!handshake_snow.is_handshake_finished());
            assert_ne!(handshake.is_my_turn(), handshake_snow.is_my_turn());

            if handshake.is_my_turn() {
                let message = handshake.write_message_vec(&payload).unwrap();
                let mut payload_recv = vec![0u8; payload.len()];
                let res = handshake_snow.read_message(&message, &mut payload_recv);

                assert_eq!(handshake.current_handshake_hash(), handshake_snow.get_handshake_hash(), "handshake hash diverged at step {step}, our turn {handshake_info}");
                assert_eq!(payload.len(), res.unwrap());
                assert_eq!(payload, payload_recv);

            } else {
                let message_len = handshake.next_message_length() + payload.len();
                // Snow needs space for a payload tag even if it doesn't need to write one.
                let mut message = vec![0u8; message_len + 16];
                assert_eq!(handshake_snow.write_message(&payload, &mut message).unwrap(), message_len);
                let res = handshake.read_message_vec(&message[0..message_len]);
                
                assert_eq!(handshake.current_handshake_hash(), handshake_snow.get_handshake_hash(), "handshake hash diverged at step {step}, snow's turn {handshake_info}");
                assert_eq!(payload, res.unwrap());
            }

            step += 1;
        }

        assert!(handshake_snow.is_handshake_finished());
        assert_eq!(handshake.remote_static(), snow_static_secret.as_ref().map(SecretKey::public).as_ref().map(PublicKey::as_ref));
        assert_eq!(handshake_snow.get_remote_static(), handshake_static_secret.as_ref().map(SecretKey::public).as_ref().map(PublicKey::as_ref));
        
        handshake_snow.into_transport_mode().unwrap();
    }
}
