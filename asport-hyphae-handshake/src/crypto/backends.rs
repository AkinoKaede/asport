use std::iter::once;

use zeroize::{Zeroize, Zeroizing};

use super::{CryptoError, SymmetricKey};

#[cfg(any(test, feature = "rustcrypto"))]
pub mod rustcrypto;

pub trait HashBackend: Default + Clone + Zeroize {
    type Hash: Clone + Zeroize + Send + Sync + 'static;

    fn initialize(&mut self, hash_protocol: &str) -> Result<(), CryptoError>;

    fn block_size(&self) -> usize;

    fn zeros(&self) -> Self::Hash;

    fn hash_into<'a> (&self, hash: &mut Self::Hash, mix_hash: bool, inputs: impl IntoIterator<Item = &'a [u8]>);

    fn hash_as_slice<'a> (&self, hash: &'a Self::Hash) -> &'a [u8];

    fn hash_as_mut_slice<'a> (&self, hash: &'a mut Self::Hash) -> &'a mut [u8];
}

pub trait AeadBackend: Default + Clone + Zeroize {
    fn initialize(&mut self, aead_protocol: &str) -> Result<(), CryptoError>;

    fn encrypt_in_place(&self, key: &SymmetricKey, nonce: u64, ad: &[u8], buffer: &mut [u8]) -> Result<(), CryptoError>;

    fn decrypt_in_place<'a> (&self, key: &SymmetricKey, nonce: u64, ad: &[u8], buffer: &'a mut [u8]) -> Result<&'a [u8], CryptoError>;

    fn header_protection_mask(&self, key: &SymmetricKey, sample: &[u8], mask: &mut [u8]) -> Result<(), CryptoError>;

    fn confidentiality_limit(&self) -> u64;

    fn integrity_limit(&self) -> u64;
}

pub trait HashExt: HashBackend {
    fn hmac<'a> (&self, key: &Self::Hash, output: &mut Self::Hash, inputs: impl IntoIterator<Item = &'a [u8]>);

    fn hkdf<'a> (&self, key: &Self::Hash, outputs: impl IntoIterator<Item = &'a mut [u8]>, input_key_materials: impl IntoIterator<Item = &'a [u8]>, info: &[u8]);
}

const MAX_BLOCK_SIZE: usize = 128;

impl <T: HashBackend> HashExt for T {
    fn hmac<'a> (&self, key: &Self::Hash, output: &mut Self::Hash, inputs: impl IntoIterator<Item = &'a [u8]>) {
        let key = self.hash_as_slice(key);
        let block_size = self.block_size();

        debug_assert!(block_size <= MAX_BLOCK_SIZE);
        debug_assert!(key.len() <= block_size);

        let mut key_scratch = Zeroizing::new([0x36u8; MAX_BLOCK_SIZE]);
        key_scratch.iter_mut().zip(key.iter()).for_each(|(ks, k)| *ks ^= k);
        let mut hmac_inner = Zeroizing::new(self.zeros());
        self.hash_into(&mut hmac_inner, false, 
            once(&key_scratch[0..block_size])
            .chain(inputs.into_iter().map(|x| x))
        );
        *key_scratch =[0x5Cu8; MAX_BLOCK_SIZE];
        key_scratch.iter_mut().zip(key.as_ref().iter()).for_each(|(ks, k)| *ks ^= k);
        self.hash_into(output, false, [&key_scratch[0..block_size], self.hash_as_slice(&hmac_inner)]);
    }

    fn hkdf<'a> (&self, key: &Self::Hash, outputs: impl IntoIterator<Item = &'a mut [u8]>, input_key_materials: impl IntoIterator<Item = &'a [u8]>, info: &[u8]) {
        let mut prk = Zeroizing::new(self.zeros());
        self.hmac(key, &mut *prk, input_key_materials);
        
        let mut output_iter = outputs.into_iter();
        let mut n = 0u8;
        let mut temp_output = Zeroizing::new(self.zeros());
        let mut last_output = Zeroizing::new(self.zeros());

        while let Some(output_truncated) = output_iter.next() {
            n = n.checked_add(1).expect("too many HKDF outputs requested");

            if n == 1 {
                self.hmac(&prk, &mut temp_output, [info, &[n]]);
            } else {
                self.hmac(&prk, &mut temp_output, [self.hash_as_slice(&last_output), info, &[n]])
            }

            self.hash_as_mut_slice(&mut last_output).copy_from_slice(self.hash_as_slice(&*temp_output));
            last_output.clone_from(&temp_output);
            let output = self.hash_as_slice(&temp_output);
            if output_truncated.len() > output.len() {
                panic!("truncated hash output cannot be longer than {}", output.len());
            }
            output_truncated.copy_from_slice(&output[0..output_truncated.len()]);
        };
    }
}
