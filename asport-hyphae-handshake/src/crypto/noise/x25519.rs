use curve25519_dalek::MontgomeryPoint;
use rand_core::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::CryptoError;

const X25519_BYTES: usize = 32;

#[derive(Default, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey ([u8; X25519_BYTES]);

impl SecretKey {
    pub const SIZE: usize = X25519_BYTES;

    pub(crate) fn new_from_rng(rng: &mut (impl CryptoRng + RngCore)) -> Self {
        let mut secret = SecretKey::default();
        rng.fill_bytes(&mut secret.0);
        secret
    }

    pub(crate) fn diffie_hellman(&self, remote_public: &PublicKey) -> SharedSecret {
        SharedSecret(remote_public.0.mul_clamped(self.0))
    }

    pub(crate) fn clone_private(&self) -> Self {
        SecretKey(self.0)
    }

    #[cfg(test)]
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn public(&self) -> PublicKey {
        PublicKey(MontgomeryPoint::mul_base_clamped(self.0))
    }

    pub(crate) fn public_from_bytes(secret: &[u8; X25519_BYTES]) -> [u8; X25519_BYTES] {
        MontgomeryPoint::mul_base_clamped(*secret).to_bytes()
    }
}

impl TryFrom<&[u8]> for SecretKey {
    type Error = CryptoError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self(value.try_into().map_err(|_| CryptoError::InvalidKeySize)?))
    }
}

#[derive(Clone, Default, Zeroize)]
pub struct PublicKey (MontgomeryPoint);

impl PublicKey {
    pub const SIZE: usize = X25519_BYTES;
}

impl TryFrom<&[u8]> for PublicKey {
    type Error = CryptoError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self(MontgomeryPoint(value.try_into().map_err(|_| CryptoError::InvalidKeySize)?)))
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

#[derive(Default, Zeroize, ZeroizeOnDrop)]
pub(crate) struct SharedSecret (MontgomeryPoint);

impl AsRef<[u8]> for SharedSecret {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

#[cfg(test)]
mod tests {
    use rand_core::OsRng;

    use super::*;

    #[test]
    fn x25519_diffie_hellman() {
        let a_secret = SecretKey::new_from_rng(&mut OsRng);
        let a_public = a_secret.public();

        let b_secret = SecretKey::new_from_rng(&mut OsRng);
        let b_public = b_secret.public();

        let a_dh = a_secret.diffie_hellman(&b_public);
        let b_dh = b_secret.diffie_hellman(&a_public);
        assert_eq!(a_dh.0, b_dh.0);
    }
}
