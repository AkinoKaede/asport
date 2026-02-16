//! RustCrypto based backends for AEAD (ChaChaPoly and AES-GCM) and
//! HKDF (BLAKE2s/b and SHA-256/512).
//! 

use aes_gcm::{aes::Aes256, Aes256Gcm};
use blake2::{Digest, digest::{FixedOutputReset, Output}};
use chacha20::{cipher::{BlockEncrypt, KeyIvInit, StreamCipher, StreamCipherSeek, StreamCipherSeekCore}, ChaCha20};
use chacha20poly1305::{aead::AeadInPlace, ChaCha20Poly1305, KeyInit};
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroize;

use crate::{crypto::{noise::{x25519::SecretKey, AskChain, HandshakeState}, transport::BuiltinTransportCrypto, CryptoBackend, HYPHAE_AEAD_NONCE_LEN, HYPHAE_AEAD_TAG_LEN}, handshake::HYPHAE_KEY_ASK_LABEL};

use crate::crypto::{CryptoError, SymmetricKey, HYPHAE_HEADER_MASK_MAX_LEN, HYPHAE_HEADER_SAMPLE_LEN};

use super::{AeadBackend, HashBackend};

pub struct RustCryptoBackend;

impl RustCryptoBackend {
    pub const X25519_KEY_SIZE: usize = SecretKey::SIZE;

    pub fn new_secret_key_into(&self, rng: &mut (impl RngCore + CryptoRng), secret_key: &mut [u8; Self::X25519_KEY_SIZE]) {
        rng.fill_bytes(secret_key.as_mut_slice());
    }

    pub fn new_secret_key(&self, rng: &mut (impl RngCore + CryptoRng)) -> [u8; Self::X25519_KEY_SIZE] {
        let mut secret_key = [0u8; Self::X25519_KEY_SIZE];
        self.new_secret_key_into(rng, &mut secret_key);
        secret_key
    }

    pub fn public_key(&self, secret_key: &[u8; Self::X25519_KEY_SIZE]) -> [u8; Self::X25519_KEY_SIZE] {
        SecretKey::public_from_bytes(secret_key)
    }
}

impl CryptoBackend for RustCryptoBackend {
    type InitialCrypto = BuiltinTransportCrypto<ChaChaPoly, Blake2s>;

    type NoiseHandshake = HandshakeState<AnyAead, AnyHash>;
    
    type TransportCrypto = BuiltinTransportCrypto<AnyAead, AnyHash>;

    type TransportRekey = AskChain<AnyHash>;

    fn protocol_supported(&self, noise_protocol: &str) -> bool {
        Self::NoiseHandshake::parse_protocol(noise_protocol).is_ok()
    }

    fn initial_crypto(&self) -> Self::InitialCrypto {
        BuiltinTransportCrypto::new(ChaChaPoly, Blake2s)
    }

    fn new_handshake(&self) -> Result<Self::NoiseHandshake, CryptoError> {
        Ok(Default::default())
    }

    fn transport_crypto(&self, handshake: &Self::NoiseHandshake) -> Result<Self::TransportCrypto, CryptoError> {
        Ok(BuiltinTransportCrypto::new(handshake.aead_backend()?, handshake.hash_backend()?))
    }

    fn export_1rtt_rekey(&self, handshake: &mut Self::NoiseHandshake, rekey: &mut Self::TransportRekey) -> Result<(), CryptoError> {
        handshake.export_ask_into(rekey, HYPHAE_KEY_ASK_LABEL)
    }
}

#[derive(Default, Clone, Zeroize)]
pub struct AnyAead (RustCryptoAeadProtocol);

#[derive(Default, Clone, Zeroize)]
enum RustCryptoAeadProtocol {
    #[default]
    Uninitialized,
    AesGcm,
    ChaChaPoly,
}

impl AnyAead {
    fn panic_uninitialized() -> ! {
        panic!("uninitialized aead backend");
    }
}

impl AeadBackend for AnyAead {
    fn initialize(&mut self, aead_protocol: &str) -> Result<(), CryptoError> {
        if aead_protocol == "AESGCM" {
            self.0 = RustCryptoAeadProtocol::AesGcm;
        } else if aead_protocol == "ChaChaPoly" {
            self.0 = RustCryptoAeadProtocol::ChaChaPoly
        } else {
            return Err(CryptoError::UnsupportedProtocol);
        }
        Ok(())
    }

    fn encrypt_in_place(&self, key: &SymmetricKey, nonce: u64, ad: &[u8], buffer: &mut [u8]) -> Result<(), CryptoError> {
        match self.0 {
            RustCryptoAeadProtocol::Uninitialized => Self::panic_uninitialized(),
            RustCryptoAeadProtocol::AesGcm => AesGcm.encrypt_in_place(key, nonce, ad, buffer),
            RustCryptoAeadProtocol::ChaChaPoly => ChaChaPoly.encrypt_in_place(key, nonce, ad, buffer)
        }
    }

    fn decrypt_in_place<'a> (&self, key: &SymmetricKey, nonce: u64, ad: &[u8], buffer: &'a mut [u8]) -> Result<&'a [u8], CryptoError> {
        match self.0 {
            RustCryptoAeadProtocol::Uninitialized => Self::panic_uninitialized(),
            RustCryptoAeadProtocol::AesGcm => AesGcm.decrypt_in_place(key, nonce, ad, buffer),
            RustCryptoAeadProtocol::ChaChaPoly => ChaChaPoly.decrypt_in_place(key, nonce, ad, buffer)
        }
    }

    fn header_protection_mask(&self, key: &SymmetricKey, sample: &[u8], mask: &mut [u8]) -> Result<(), CryptoError> {
        match self.0 {
            RustCryptoAeadProtocol::Uninitialized => Self::panic_uninitialized(),
            RustCryptoAeadProtocol::AesGcm => AesGcm.header_protection_mask(key, sample, mask),
            RustCryptoAeadProtocol::ChaChaPoly => ChaChaPoly.header_protection_mask(key, sample, mask),
        }
    }

    fn confidentiality_limit(&self) -> u64 {
        match self.0 {
            RustCryptoAeadProtocol::Uninitialized => Self::panic_uninitialized(),
            RustCryptoAeadProtocol::AesGcm => AesGcm.confidentiality_limit(),
            RustCryptoAeadProtocol::ChaChaPoly => ChaChaPoly.confidentiality_limit(),
        }
    }

    fn integrity_limit(&self) -> u64 {
        match self.0 {
            RustCryptoAeadProtocol::Uninitialized => Self::panic_uninitialized(),
            RustCryptoAeadProtocol::AesGcm => AesGcm.integrity_limit(),
            RustCryptoAeadProtocol::ChaChaPoly => ChaChaPoly.integrity_limit(),
        }
    }
}

#[derive(Default, Clone, Zeroize)]
pub struct AesGcm;

impl AesGcm {
    fn nonce(nonce_u64: u64) -> [u8; HYPHAE_AEAD_NONCE_LEN] {
        let mut nonce = [0u8; HYPHAE_AEAD_NONCE_LEN];
        nonce[4..].copy_from_slice(&nonce_u64.to_be_bytes());
        nonce
    }
}

impl AeadBackend for AesGcm {
    fn initialize(&mut self, aead_protocol: &str) -> Result<(), CryptoError> {
        if aead_protocol == "AESGCM" {
            Ok(())
        } else {
            Err(CryptoError::InvalidProtocol)
        }
    }

    fn encrypt_in_place(&self, packet_key: &SymmetricKey, packet_id: u64, ad: &[u8], buffer: &mut [u8]) -> Result<(), CryptoError> {
        if buffer.len() < HYPHAE_AEAD_TAG_LEN {
            return Err(CryptoError::Internal);
        }

        let (packet, tag) = buffer.split_at_mut(buffer.len() - HYPHAE_AEAD_TAG_LEN);
        let aead = Aes256Gcm::new(packet_key.as_ref().into());
        let tag_temp = aead.encrypt_in_place_detached(Self::nonce(packet_id).as_ref().into(), ad, packet)
            .map_err(|_| CryptoError::Internal)?;
        tag.copy_from_slice(&tag_temp);
        Ok(())
    }

    fn decrypt_in_place<'a> (&self, packet_key: &SymmetricKey, packet_id: u64, ad: &[u8], buffer: &'a mut [u8]) -> Result<&'a [u8], CryptoError> {
        if buffer.len() < HYPHAE_AEAD_TAG_LEN {
            return Err(CryptoError::Internal);
        }
        let (packet, tag) = buffer.split_at_mut(buffer.len() - HYPHAE_AEAD_TAG_LEN);

        let aead = Aes256Gcm::new(packet_key.as_ref().into());
        aead.decrypt_in_place_detached(Self::nonce(packet_id).as_ref().into(), ad, packet, tag.as_ref().into())
            .map_err(|_| CryptoError::DecryptionFailed)?;
        
        Ok(packet)
    }

    fn header_protection_mask(&self, header_key: &SymmetricKey, sample: &[u8], mask: &mut [u8]) -> Result<(), CryptoError> {
        if sample.len() != HYPHAE_HEADER_SAMPLE_LEN ||
           mask.len() > HYPHAE_HEADER_MASK_MAX_LEN
        {
            return Err(CryptoError::Internal)
        }

        let mut sample_block = [0u8; HYPHAE_HEADER_SAMPLE_LEN];
        sample_block.copy_from_slice(sample);

        let cipher = Aes256::new(header_key.as_ref().into());
        cipher.encrypt_block(&mut sample_block.into());
        mask.copy_from_slice(&sample_block[0..mask.len()]);

        Ok(())
    }
    
    fn confidentiality_limit(&self) -> u64 {
        2u64.pow(23)
    }
    
    fn integrity_limit(&self) -> u64 {
        2u64.pow(52)
    }
}

#[derive(Default, Clone, Zeroize)]
pub struct ChaChaPoly;

impl ChaChaPoly {
    fn nonce(nonce_u64: u64) -> [u8; HYPHAE_AEAD_NONCE_LEN] {
        let mut nonce = [0u8; HYPHAE_AEAD_NONCE_LEN];
        nonce[4..].copy_from_slice(&nonce_u64.to_le_bytes());
        nonce
    }
}

impl AeadBackend for ChaChaPoly {
    fn initialize(&mut self, aead_protocol: &str) -> Result<(), CryptoError> {
        if aead_protocol == "ChaChaPoly" {
            Ok(())
        } else {
            Err(CryptoError::InvalidProtocol)
        }
    }

    fn encrypt_in_place(&self, packet_key: &SymmetricKey, packet_id: u64, ad: &[u8], buffer: &mut [u8]) -> Result<(), CryptoError> {
        if buffer.len() < HYPHAE_AEAD_TAG_LEN {
            return Err(CryptoError::Internal);
        }

        let (packet, tag) = buffer.split_at_mut(buffer.len() - HYPHAE_AEAD_TAG_LEN);
        let aead = ChaCha20Poly1305::new(packet_key.as_ref().into());
        let tag_temp = aead.encrypt_in_place_detached(Self::nonce(packet_id).as_ref().into(), ad, packet)
            .map_err(|_| CryptoError::Internal)?;
        tag.copy_from_slice(&tag_temp);
        Ok(())
    }

    fn decrypt_in_place<'a> (&self, packet_key: &SymmetricKey, packet_id: u64, ad: &[u8], buffer: &'a mut [u8]) -> Result<&'a [u8], CryptoError> {
        if buffer.len() < HYPHAE_AEAD_TAG_LEN {
            return Err(CryptoError::Internal);
        }
        let (packet, tag) = buffer.split_at_mut(buffer.len() - HYPHAE_AEAD_TAG_LEN);

        let aead = ChaCha20Poly1305::new(packet_key.as_ref().into());
        aead.decrypt_in_place_detached(Self::nonce(packet_id).as_ref().into(), ad, packet, tag.as_ref().into())
            .map_err(|_| CryptoError::DecryptionFailed)?;
        
        Ok(packet)
    }

    fn header_protection_mask(&self, header_key: &SymmetricKey, sample: &[u8], mask: &mut [u8]) -> Result<(), CryptoError> {
        if sample.len() != HYPHAE_HEADER_SAMPLE_LEN ||
           mask.len() > HYPHAE_HEADER_MASK_MAX_LEN
        {
            return Err(CryptoError::Internal)
        }

        let block = u32::from_le_bytes(sample[0..4].try_into().unwrap());
        let nonce: &[u8; HYPHAE_AEAD_NONCE_LEN] = sample[4..].try_into().unwrap();
        let mut cipher = ChaCha20::new(header_key.as_ref().into(), nonce.into());
        
        cipher.seek(block as u64 * 64);
        debug_assert_eq!(cipher.get_core().get_block_pos(), block);

        mask.zeroize();
        cipher.apply_keystream(mask);

        Ok(())
    }
    
    fn confidentiality_limit(&self) -> u64 {
        // Not a placeholder, the ChaChaPoly confidentiality limit
        // exceeds the maximum representable packet ID.
        u64::MAX
    }
    
    fn integrity_limit(&self) -> u64 {
        2u64.pow(36)
    }
}

#[derive(Default, Clone, Zeroize)]
pub struct AnyHash (RustCryptoHashProtocol);

#[derive(Default, Clone, Zeroize)]
enum RustCryptoHashProtocol {
    #[default]
    Uninitialized,
    Blake2s,
    Blake2b,
    Sha256,
    Sha512,
}

impl AnyHash {
    fn panic_uninitialized() -> ! {
        panic!("uninitialized hash backend");
    }

    fn hash_len(&self) -> usize {
        match self.0 {
            RustCryptoHashProtocol::Uninitialized => Self::panic_uninitialized(),
            RustCryptoHashProtocol::Blake2s |
            RustCryptoHashProtocol::Sha256 => 32,
            RustCryptoHashProtocol::Blake2b |
            RustCryptoHashProtocol::Sha512 => 64,
        }
    }
}

impl HashBackend for AnyHash {
    type Hash = [u8; 64];

    fn initialize(&mut self, hash_protocol: &str) -> Result<(), CryptoError> {
        if hash_protocol == "BLAKE2s" {
            self.0 = RustCryptoHashProtocol::Blake2s;
        } else if hash_protocol == "BLAKE2b" {
            self.0 = RustCryptoHashProtocol::Blake2b;
        } else if hash_protocol == "SHA256" {
            self.0 = RustCryptoHashProtocol::Sha256;
        } else if hash_protocol == "SHA512" {
            self.0 = RustCryptoHashProtocol::Sha512;
        } else {
            return Err(CryptoError::UnsupportedProtocol);
        }
        Ok(())
    }

    fn block_size(&self) -> usize {
        self.hash_len() * 2
    }

    fn zeros(&self) -> Self::Hash {
        [0u8; 64]
    }

    fn hash_into<'a> (&self, hash: &mut Self::Hash, mix_hash: bool, inputs: impl IntoIterator<Item = &'a [u8]>) {
        match self.0 {
            RustCryptoHashProtocol::Uninitialized => Self::panic_uninitialized(),
            RustCryptoHashProtocol::Blake2s => Blake2s.hash_into((&mut hash[0..32]).try_into().unwrap(), mix_hash, inputs),
            RustCryptoHashProtocol::Blake2b => Blake2b.hash_into(hash, mix_hash, inputs),
            RustCryptoHashProtocol::Sha256 => Sha256.hash_into((&mut hash[0..32]).try_into().unwrap(), mix_hash, inputs),
            RustCryptoHashProtocol::Sha512 => Sha512.hash_into(hash, mix_hash, inputs),
        }
    }

    fn hash_as_slice<'a> (&self, hash: &'a Self::Hash) -> &'a [u8] {
        let len = self.hash_len();
        &hash[0..len]
    }

    fn hash_as_mut_slice<'a> (&self, hash: &'a mut Self::Hash) -> &'a mut [u8] {  
        let len = self.hash_len();
        &mut hash[0..len]
    }
}

#[derive(Default, Clone, Zeroize)]
pub struct Blake2s;

impl HashBackend for Blake2s {
    type Hash = [u8; 32];

    fn initialize(&mut self, hash_protocol: &str) -> Result<(), CryptoError> {
        if hash_protocol == "BLAKE2s" {
            Ok(())
        } else {
            Err(CryptoError::InvalidProtocol)
        }
    }

    fn block_size(&self) -> usize {
        64
    }

    fn zeros(&self) -> Self::Hash {
        Self::Hash::default()
    }

    fn hash_into<'a> (&self, hash: &mut Self::Hash, mix_hash: bool, inputs: impl IntoIterator<Item = &'a [u8]>) {
        hash_into_with_digest::<blake2::Blake2s256>(hash.into(), mix_hash, inputs);
    }

    fn hash_as_slice<'a> (&self, hash: &'a Self::Hash) -> &'a [u8] {
        hash.as_slice()
    }

    fn hash_as_mut_slice<'a> (&self, hash: &'a mut Self::Hash) -> &'a mut [u8] {
        hash.as_mut_slice()
    }
}

#[derive(Default, Clone, Zeroize)]
pub struct Blake2b;

impl HashBackend for Blake2b {
    type Hash = [u8; 64];

    fn initialize(&mut self, hash_protocol: &str) -> Result<(), CryptoError> {
        if hash_protocol == "BLAKE2b" {
            Ok(())
        } else {
            Err(CryptoError::InvalidProtocol)
        }
    }

    fn block_size(&self) -> usize {
        128
    }

    fn zeros(&self) -> Self::Hash {
        [0u8; 64]
    }

    fn hash_into<'a> (&self, hash: &mut Self::Hash, mix_hash: bool, inputs: impl IntoIterator<Item = &'a [u8]>) {
        hash_into_with_digest::<blake2::Blake2b512>(hash.into(), mix_hash, inputs);
    }

    fn hash_as_slice<'a> (&self, hash: &'a Self::Hash) -> &'a [u8] {
        hash.as_slice()
    }

    fn hash_as_mut_slice<'a> (&self, hash: &'a mut Self::Hash) -> &'a mut [u8] {
        hash.as_mut_slice()
    }
}

#[derive(Default, Clone, Zeroize)]
pub struct Sha256;

impl HashBackend for Sha256 {
    type Hash = [u8; 32];

    fn initialize(&mut self, hash_protocol: &str) -> Result<(), CryptoError> {
        if hash_protocol == "SHA256" {
            Ok(())
        } else {
            Err(CryptoError::InvalidProtocol)
        }
    }

    fn block_size(&self) -> usize {
        64
    }

    fn zeros(&self) -> Self::Hash {
        [0u8; 32]
    }

    fn hash_into<'a> (&self, hash: &mut Self::Hash, mix_hash: bool, inputs: impl IntoIterator<Item = &'a [u8]>) {
        hash_into_with_digest::<sha2::Sha256>(hash.into(), mix_hash, inputs);
    }

    fn hash_as_slice<'a> (&self, hash: &'a Self::Hash) -> &'a [u8] {
        hash.as_slice()
    }

    fn hash_as_mut_slice<'a> (&self, hash: &'a mut Self::Hash) -> &'a mut [u8] {
        hash.as_mut_slice()
    }
}

#[derive(Default, Clone, Zeroize)]
pub struct Sha512;

impl HashBackend for Sha512 {
    type Hash = [u8; 64];

    fn initialize(&mut self, hash_protocol: &str) -> Result<(), CryptoError> {
        if hash_protocol == "SHA512" {
            Ok(())
        } else {
            Err(CryptoError::InvalidProtocol)
        }
    }

    fn block_size(&self) -> usize {
        128
    }

    fn zeros(&self) -> Self::Hash {
        [0u8; 64]
    }

    fn hash_into<'a> (&self, hash: &mut Self::Hash, mix_hash: bool, inputs: impl IntoIterator<Item = &'a [u8]>) {
        hash_into_with_digest::<sha2::Sha512>(hash.into(), mix_hash, inputs);
    }

    fn hash_as_slice<'a> (&self, hash: &'a Self::Hash) -> &'a [u8] {
        hash.as_slice()
    }

    fn hash_as_mut_slice<'a> (&self, hash: &'a mut Self::Hash) -> &'a mut [u8] {
        hash.as_mut_slice()
    }
}

fn hash_into_with_digest<'a, D: Digest + FixedOutputReset> (hash: &mut Output<D>, mix_hash: bool, inputs: impl IntoIterator<Item = &'a [u8]>) {
    // Todo: RustCrypto's hashers don't support zeroize until 0.11.
    // For now, reset and hope for the best...
    let mut digest = match mix_hash {
        true => D::new_with_prefix(&hash),
        false => D::new(),
    };
    inputs.into_iter().for_each(|input| Digest::update(&mut digest, input));
    Digest::finalize_into_reset(&mut digest, hash);
}

#[cfg(test)]
mod tests {
    use hmac::Mac;
    use rand_core::{OsRng, RngCore};

    use crate::crypto::backends::HashExt;

    use super::*;

    fn random_hash<H: HashBackend> (hash_impl: &H) -> H::Hash {
        let mut random_hash = hash_impl.zeros();
        OsRng.fill_bytes(hash_impl.hash_as_mut_slice(&mut random_hash));
        random_hash
    }

    #[test]
    fn rustcrypto_hmac() {
        let inputs = [b"hello".as_slice(), b"world".as_slice()];

        let key = random_hash(&Blake2s);
        let mut hmac = Blake2s.zeros();
        Blake2s.hmac(&key,&mut hmac, inputs.iter().copied());

        let mut hmac_rc_inst: hmac::SimpleHmac<blake2::Blake2s256> = <hmac::SimpleHmac<blake2::Blake2s256> as Mac>::new_from_slice(key.as_ref()).unwrap();
        inputs.into_iter().for_each(|input| hmac_rc_inst.update(input));
        let hmac_rc = hmac_rc_inst.finalize().into_bytes();
        assert_eq!(hmac.as_ref(), hmac_rc.as_slice());
    }

    #[test]
    fn rustcrypto_hkdf() {
        let key = random_hash(&Blake2s);
        let ikm = [b"hello".as_slice(), b"world".as_slice()];
        let ikm_rc = b"helloworld";
        let info = b"foobar".as_slice();

        let mut output1 = Blake2s.zeros();
        let mut output2 = [0u8; 16];
        let mut output3 = Blake2s.zeros();

        Blake2s.hkdf(&key, [output1.as_mut(), output2.as_mut(), output3.as_mut()], ikm.iter().copied(), info);

        let hk_inst_rc = hkdf::SimpleHkdf::<blake2::Blake2s256>::new(Some(key.as_ref()), ikm_rc);
        let mut output_rc = [0u8; 32 * 3];
        hk_inst_rc.expand(info, &mut output_rc).unwrap();

        assert_eq!(output1.as_ref(), &output_rc[0..32]);
        assert_eq!(output2.as_ref(), &output_rc[32..48]);
        assert_eq!(output3.as_ref(), &output_rc[64..]);
    }
}
