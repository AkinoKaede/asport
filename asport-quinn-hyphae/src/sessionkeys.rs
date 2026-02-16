use hyphae_handshake::{crypto::{InitialCrypto, SymmetricKey, TransportCrypto, HYPHAE_AEAD_TAG_LEN, HYPHAE_HEADER_SAMPLE_LEN}, handshake::{HandshakeVersion, HYPHAE_INIT_DATA_HKDF_LABEL, HYPHAE_INIT_HP_HKDF_LABEL, HYPHAE_RESP_DATA_HKDF_LABEL, HYPHAE_RESP_HP_HKDF_LABEL}};
use quinn_proto::crypto;

pub fn keys_from_level_secret(
    local_is_initiator: bool,
    level_secret: &SymmetricKey,
    driver: &(impl TransportCrypto + Send + Sync + 'static)
) -> crypto::Keys
{
    crypto::Keys {
        header: crypto::KeyPair {
            local: HeaderProtectionKey::new(local_is_initiator, level_secret, driver.clone()),
            remote: HeaderProtectionKey::new(!local_is_initiator, level_secret, driver.clone()),
        },
        packet: packet_keys_from_level_secret(local_is_initiator, level_secret, driver)
    }
}

pub fn packet_keys_from_level_secret(
    local_is_initiator: bool,
    level_secret: &SymmetricKey,
    driver: &(impl TransportCrypto + Send + Sync + 'static)
) -> crypto::KeyPair<Box<dyn crypto::PacketKey>>
{
    crypto::KeyPair {
        local: PacketProtectionKey::new(local_is_initiator, level_secret, driver.clone()),
        remote: PacketProtectionKey::new(!local_is_initiator, level_secret, driver.clone()),
    }
}

pub fn initial_keys(
    local_is_initiator: bool,
    handshake_version: HandshakeVersion,
    transport_label: &[u8],
    client_dcid: &[u8],
    initial_crypto: &(impl InitialCrypto + Send + Sync + 'static)
) -> crypto::Keys
{
    let mut intial_secret = SymmetricKey::default();
    initial_crypto.initial_level_secret(handshake_version, transport_label, client_dcid, &mut intial_secret)
        .expect("initial crypto can calculate initial keys");
    keys_from_level_secret(local_is_initiator, &intial_secret, initial_crypto)
}


struct HeaderProtectionKey<C: TransportCrypto> {
    driver: C,
    key: SymmetricKey,
}

impl <C: TransportCrypto> HeaderProtectionKey<C> {
    fn apply(&self, encrypt: bool, pn_offset: usize, packet: &mut [u8]) {
        let mut mask = [0u8; 5];
        let sample_start = pn_offset + 4;
        self.driver.header_protection_mask(&self.key, &packet[sample_start..sample_start + HYPHAE_HEADER_SAMPLE_LEN], &mut mask)
            .expect("transport crypto can calculate header mask");

        let header_0_orig = packet[0];
        if packet[0] & 0x80 == 0x80 {
            packet[0] ^= mask[0] & 0x0f;
        } else {
            packet[0] ^= mask[0] & 0x1f;
        }

        let pn_len = if encrypt {
            (header_0_orig & 0x03) as usize + 1
        } else {
            (packet[0] & 0x03) as usize + 1
        };

        packet[pn_offset..pn_offset + pn_len]
            .iter_mut()
            .zip(mask[1..].iter())
            .for_each(|(p, m)| *p ^= m);
    }
}

impl <C: TransportCrypto + Send + Sync + 'static> HeaderProtectionKey<C> {
    pub fn new(initiator: bool, level_secret: &SymmetricKey, driver: C) -> Box<dyn crypto::HeaderKey> {
        let mut this = Box::new(Self {
            driver,
            key: SymmetricKey::default(),
        });
        let label = match initiator {
            true => HYPHAE_INIT_HP_HKDF_LABEL,
            false => HYPHAE_RESP_HP_HKDF_LABEL,
        };
        this.driver.derive_subkey(level_secret, label, &mut this.key);
        this
    }
}

impl <C: TransportCrypto + Send + Sync + 'static> crypto::HeaderKey for HeaderProtectionKey<C> {
    fn decrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        self.apply(false, pn_offset, packet);
    }

    fn encrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        self.apply(true, pn_offset, packet);
    }

    fn sample_size(&self) -> usize {
        HYPHAE_HEADER_SAMPLE_LEN
    }
}

struct PacketProtectionKey<C: TransportCrypto> {
    driver: C,
    key: SymmetricKey,
}

impl <C: TransportCrypto + Send + Sync + 'static> PacketProtectionKey<C> {
    pub fn new(initiator: bool, level_secret: &SymmetricKey, driver: C) -> Box<dyn crypto::PacketKey> {
        let mut this = Box::new(Self {
            driver,
            key: SymmetricKey::default(),
        });
        let label = match initiator {
            true => HYPHAE_INIT_DATA_HKDF_LABEL,
            false => HYPHAE_RESP_DATA_HKDF_LABEL,
        };
        this.driver.derive_subkey(level_secret, label, &mut this.key);
        this
    }
}

impl <C: TransportCrypto + Send + Sync + 'static> crypto::PacketKey for PacketProtectionKey<C> {
    fn encrypt(&self, packet: u64, buf: &mut [u8], header_len: usize) {
        let (header, payload) = buf.split_at_mut(header_len);
        self.driver.encrypt_in_place(&self.key, packet, header, payload)
            .expect("transport crypto can encrypt packet");
    }

    fn decrypt(
        &self,
        packet: u64,
        header: &[u8],
        payload: &mut bytes::BytesMut,
    ) -> Result<(), crypto::CryptoError> {
        let buffer = payload.as_mut();
        let payload_len = self.driver.decrypt_in_place(&self.key, packet, header, buffer)
            .map(|x| x.len())
            .map_err(|_| crypto::CryptoError)?;
        payload.truncate(payload_len);
        Ok(())
    }

    fn tag_len(&self) -> usize {
        HYPHAE_AEAD_TAG_LEN
    }

    fn confidentiality_limit(&self) -> u64 {
        self.driver.aead_confidentiality_limit()
    }

    fn integrity_limit(&self) -> u64 {
        self.driver.aead_integrity_limit()
    }
}
