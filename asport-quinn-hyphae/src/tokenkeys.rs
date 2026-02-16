//! Adapters from a Hyphae `CryptoBackend` to Quinn's reset and retry
//! token generation traits.
//! 
//! These can be used in place of Quinn's dependency on Ring to generate
//! reset and retry tokens.
//! 

use hyphae_handshake::crypto::{SymmetricKey, SyncCryptoBackend, TransportCrypto, HYPHAE_AEAD_TAG_LEN};
use quinn_proto::crypto::{AeadKey, HandshakeTokenKey, HmacKey};
use rand_core::{OsRng, RngCore};

pub struct HyphaeHmacKey<B: SyncCryptoBackend> {
    crypto: B::InitialCrypto,
    key: <B::InitialCrypto as TransportCrypto>::Hash,
}

impl <B: SyncCryptoBackend> HyphaeHmacKey<B> {
    pub fn new(crypto_backend: &B) -> Self {
        let crypto = crypto_backend.initial_crypto();
        let mut key = crypto.zeros_hash();
        OsRng.fill_bytes(crypto.hash_as_mut_slice(&mut key));
        Self {
            crypto,
            key,
        }
    }
}

impl <B: SyncCryptoBackend> HmacKey for HyphaeHmacKey<B> {
    fn sign(&self, data: &[u8], signature_out: &mut [u8]) {
        let mut sig = self.crypto.zeros_hash();
        self.crypto.hkdf(&self.key, data, b"", &mut sig);
        signature_out.copy_from_slice(self.crypto.hash_as_slice(&sig));
    }

    fn signature_len(&self) -> usize {
        self.crypto.hash_as_slice(&self.crypto.zeros_hash()).len()
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), quinn_proto::crypto::CryptoError> {
        let mut sig = self.crypto.zeros_hash();
        self.crypto.hkdf(&self.key, data, b"", &mut sig);
        if self.crypto.hash_as_slice(&sig) == signature {
            Ok(())
        } else {
            Err(quinn_proto::crypto::CryptoError)
        }
    }
}
pub struct HyphaeHandshakeTokenKey<B: SyncCryptoBackend> {
    crypto: B::InitialCrypto,
    key: <B::InitialCrypto as TransportCrypto>::Hash,
}

impl <B: SyncCryptoBackend> HyphaeHandshakeTokenKey<B> {
    pub fn new(crypto_backend: &B) -> Self {
        let crypto = crypto_backend.initial_crypto();
        let mut key = crypto.zeros_hash();
        OsRng.fill_bytes(crypto.hash_as_mut_slice(&mut key));
        Self {
            crypto,
            key,
        }
    }
}

impl <B: SyncCryptoBackend> HandshakeTokenKey for HyphaeHandshakeTokenKey<B> {
    fn aead_from_hkdf(&self, random_bytes: &[u8]) -> Box<dyn AeadKey> {
        let mut aead_key_hash = self.crypto.zeros_hash();
        self.crypto.hkdf(&self.key, random_bytes, b"", &mut aead_key_hash);
        let mut aead_key = SymmetricKey::default();
        aead_key.as_mut().copy_from_slice(&self.crypto.hash_as_slice(&aead_key_hash)[0..SymmetricKey::SIZE]);
        Box::new(
            HyphaeAeadKey::<B> {
                crypto: self.crypto.clone(),
                key: aead_key,
            }
        )
    }
}

pub struct HyphaeAeadKey<B: SyncCryptoBackend> {
    crypto: B::InitialCrypto,
    key: SymmetricKey,
}

impl <B: SyncCryptoBackend> AeadKey for HyphaeAeadKey<B> {
    fn seal(&self, data: &mut Vec<u8>, additional_data: &[u8]) -> Result<(), quinn_proto::crypto::CryptoError> {
        data.extend_from_slice(&[0u8; HYPHAE_AEAD_TAG_LEN]);
        self.crypto.encrypt_in_place(&self.key, 0, additional_data, data.as_mut_slice())
            .map_err(|_| quinn_proto::crypto::CryptoError)
    }

    fn open<'a>(
        &self,
        data: &'a mut [u8],
        additional_data: &[u8],
    ) -> Result<&'a mut [u8], quinn_proto::crypto::CryptoError> {
        let len = self.crypto.decrypt_in_place(&self.key, 0, additional_data, data)
            .map_err(|_| quinn_proto::crypto::CryptoError)?
            .len();
        Ok(&mut data[0..len])
    }
}
