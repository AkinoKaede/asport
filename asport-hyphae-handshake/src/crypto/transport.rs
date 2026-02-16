use std::iter::once;

use crate::handshake::{HandshakeVersion, HYPHAE_INITIAL_SECRET_HKDF_LABEL, HYPHAE_RETRY_SECRET_HKDF_LABEL};

use super::{backends::{AeadBackend, HashBackend, HashExt}, CryptoError, InitialCrypto, SymmetricKey, TransportCrypto};

#[derive(Clone)]
pub struct BuiltinTransportCrypto<A: AeadBackend, H: HashBackend> {
    aead_impl: A,
    hash_impl: H,
}

impl <A: AeadBackend, H: HashBackend> BuiltinTransportCrypto<A, H> {
    pub fn new(aead_impl: A, hash_impl: H) -> Self {
        Self {
            aead_impl,
            hash_impl,
        }
    }
}

impl <A: AeadBackend, H: HashBackend> TransportCrypto for BuiltinTransportCrypto<A, H> {
    type Hash = H::Hash;

    fn zeros_hash(&self) -> Self::Hash {
        self.hash_impl.zeros()
    }

    fn hash_into(&self, message: &[u8], output: &mut Self::Hash) {
        self.hash_impl.hash_into(output, false, once(message));
    }
    
    fn hkdf(&self, key: &Self::Hash, ikm: &[u8], info: &[u8], output: &mut Self::Hash) {
        let output_mut = self.hash_impl.hash_as_mut_slice(output);
        self.hash_impl.hkdf(key, once(output_mut), once(ikm), info);
    }

    fn hash_as_slice<'a> (&self, hash: &'a Self::Hash) -> &'a [u8] {
        self.hash_impl.hash_as_slice(hash)
    }
    
    fn hash_as_mut_slice<'a> (&self, hash: &'a mut Self::Hash) -> &'a mut [u8] {
        self.hash_impl.hash_as_mut_slice(hash)
    }
    
    fn derive_subkey(&self, level_secret: &super::SymmetricKey, label: &[u8], output: &mut super::SymmetricKey) {
        derive_subkey(&self.hash_impl, level_secret, label, output);
    }

    fn aead_confidentiality_limit(&self) -> u64 {
        self.aead_impl.confidentiality_limit()
    }

    fn aead_integrity_limit(&self) -> u64 {
        self.aead_impl.integrity_limit()
    }

    fn encrypt_in_place(&self, packet_key: &super::SymmetricKey, packet_id: u64, ad: &[u8], buffer: &mut [u8]) -> Result<(), CryptoError> {
        self.aead_impl.encrypt_in_place(packet_key, packet_id, ad, buffer)
    }

    fn decrypt_in_place<'a> (&self, packet_key: &super::SymmetricKey, packet_id: u64, ad: &[u8], buffer: &'a mut [u8]) -> Result<&'a [u8], CryptoError> {
        self.aead_impl.decrypt_in_place(packet_key, packet_id, ad, buffer)
    }

    fn header_protection_mask(&self, header_key: &SymmetricKey, sample: &[u8], mask: &mut [u8]) -> Result<(), CryptoError> {
        self.aead_impl.header_protection_mask(header_key, sample, mask)
    }
}

impl <A: AeadBackend, H: HashBackend> InitialCrypto for BuiltinTransportCrypto<A, H> {
    fn initial_level_secret(&self, handshake_version: HandshakeVersion, transport_label: &[u8], client_dcid: &[u8], level_secret: &mut SymmetricKey) -> Result<(), CryptoError> {
        client_dcid_secret(&self.hash_impl, handshake_version, transport_label, client_dcid, HYPHAE_INITIAL_SECRET_HKDF_LABEL, level_secret)
    }

    fn retry_tag_secret(&self, handshake_version: HandshakeVersion, transport_label: &[u8], client_dcid: &[u8], level_secret: &mut SymmetricKey) -> Result<(), CryptoError> {
        client_dcid_secret(&self.hash_impl, handshake_version, transport_label, client_dcid, HYPHAE_RETRY_SECRET_HKDF_LABEL, level_secret)
    }
}

fn client_dcid_secret(hash_impl: &impl HashBackend, handshake_version: HandshakeVersion, transport_label: &[u8], client_dcid: &[u8], label: &[u8], level_secret: &mut SymmetricKey) -> Result<(), CryptoError> {
    if transport_label.is_empty() {
        return Err(CryptoError::Internal);
    }

    let ikm = 
        once(handshake_version.label())
        .chain(once(b".".as_slice()))
        .chain(once(transport_label))
        .chain(once(b".".as_slice()))
        .chain(once(client_dcid));

    hash_impl.hkdf(
        &hash_impl.zeros(),
        once(level_secret.as_mut().as_mut_slice()),
        ikm,
        label);
    Ok(())
}

fn derive_subkey(hash_impl: &impl HashBackend, level_secret: &SymmetricKey, label: &[u8], output: &mut SymmetricKey) {
    hash_impl.hkdf(&hash_impl.zeros(), once(output.as_mut().as_mut_slice()), once(level_secret.as_ref().as_slice()), label);
}
