//! Implementation of the Noise Additional Symmetric Keys proposal.
//! 
//! See: https://raw.githubusercontent.com/rot256/noise-extension-ask/master/output/ask.pdf

use std::iter::once;

use crate::crypto::{backends::{HashBackend, HashExt}, CryptoError, SymmetricKey};

use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct AskChain<H: HashBackend> { 
    pub(crate) hash_impl: H,
    pub(crate) ask_ck: Option<H::Hash>,
}

impl <H: HashBackend> Default for AskChain<H> {
    fn default() -> Self {
        Self { hash_impl: Default::default(), ask_ck: Default::default() }
    }
}

impl <H: HashBackend> AskChain<H> {
    pub fn get_ask_into(&mut self, key: &mut SymmetricKey) -> Result<(), CryptoError> {
        if let Some(ask_ck) = self.ask_ck.as_mut() {
            let mut next_ask_ck = self.hash_impl.zeros();
            self.hash_impl.hkdf(ask_ck, [self.hash_impl.hash_as_mut_slice(&mut next_ask_ck), key.as_mut()], once(b"".as_slice()), b"");
            ask_ck.clone_from(&next_ask_ck);
            next_ask_ck.zeroize();
            Ok(())
        } else {
            Err(CryptoError::InvalidState)
        }
    }

    pub fn initialized(&self) -> bool {
        self.ask_ck.is_some()
    }

    pub fn reset(&mut self) {
        self.ask_ck.zeroize();
    }
}

impl <H: HashBackend> crate::crypto::TransportRekey for AskChain<H> {
    fn next_1rtt_secret(&mut self, level_secret: &mut SymmetricKey) {
        if let Err(_) = self.get_ask_into(level_secret) {
            panic!("rekey not initialized");
        }
    }
}

/*
#[cfg(test)]
mod tests {
    use rand_core::OsRng;

    use crate::crypto::{backends::rustcrypto::{Blake2s, ChaChaPoly}, noise::HandshakeState};

    use super::*;

    
    #[test]
    fn additional_symmetric_keys() {
        let mut handshake: HandshakeState<ChaChaPoly, Blake2s> = HandshakeState::default();
        
        let mut ask1 = AskChain::default();
        let mut ask2 = AskChain::default();
        assert!(ask1.get_ask_into(&mut SymmetricKey::default()).is_err());

        handshake.initialize_ask_into(&mut ask1, b"chain1").unwrap_err();
        handshake.initialize(&mut OsRng, "Noise_NN_25519_ChaChaPoly_BLAKE2s", true, once(b"".as_slice()), None, None).unwrap();
        
        handshake.initialize_ask_into(&mut ask1, b"chain1").unwrap();
        handshake.initialize_ask_into(&mut ask2, b"chain2").unwrap();

        let mut key1_1 = SymmetricKey::default();
        let mut key1_2 = SymmetricKey::default();
        let mut key2_1 = SymmetricKey::default();
        ask1.get_ask_into(&mut key1_1).unwrap();
        ask1.get_ask_into(&mut key1_2).unwrap();
        ask2.get_ask_into(&mut key2_1).unwrap();
        assert_ne!(key1_1.as_ref(), key1_2.as_ref());
        assert_ne!(key1_1.as_ref(), key2_1.as_ref());

        ask1.reset();
        assert!(ask1.get_ask_into(&mut SymmetricKey::default()).is_err());
    }
}
*/