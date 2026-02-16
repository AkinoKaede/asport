use rand_core::OsRng;

use crate::{buffer::Buffer, crypto::{noise::x25519::{PublicKey, SecretKey}, CryptoError, SecretKeySetup}, customization::{HandshakeConfig, HandshakeDriver, HandshakeInfo, PayloadDriver}, Error};

pub struct HandshakeBuilder<'a, T: PayloadDriver + Clone> {
    protocol: &'static str,
    s: Option<&'a [u8]>,
    rs: Option<&'a [u8]>,
    payload_driver: T,
}

impl <'a> HandshakeBuilder<'a, DefaultPayloadDriver> {
    pub fn new(protocol: &'static str) -> Self {
        HandshakeBuilder {
            protocol,
            s: None,
            rs: None,
            payload_driver: DefaultPayloadDriver,
        }
    }
}

impl <'a, T: PayloadDriver + Clone> HandshakeBuilder<'a, T> {
    pub fn with_static_key(mut self, s: &'a [u8]) -> Self {
        self.s = Some(s);
        self
    }

    pub fn with_remote_public(mut self, rs: &'a [u8]) -> Self {
        self.rs = Some(rs);
        self
    }

    pub fn with_cloned_payload_driver<TT: PayloadDriver + Clone> (self, payload_driver: TT) -> HandshakeBuilder<'a, TT> {
        HandshakeBuilder {
            payload_driver,
            protocol: self.protocol,
            s: self.s,
            rs: self.rs,
        }
    }

    pub fn build(self) -> Result<BasicHandshakeConfig<T>, CryptoError> {
        Ok(BasicHandshakeConfig {
            protocol: self.protocol,
            s: match self.s {
                Some(s) => Some(s.try_into()?),
                None => None,
            },
            rs: match self.rs {
                Some(rs) => Some(rs.try_into()?),
                None => None,
            },
            payload_driver: self.payload_driver,
        })
    }
}

pub struct BasicHandshakeConfig<T: PayloadDriver + Clone> {
    protocol: &'static str,
    s: Option<SecretKey>,
    rs: Option<PublicKey>,
    payload_driver: T,
}



impl<T: PayloadDriver + Clone> HandshakeConfig for BasicHandshakeConfig<T> {
    type Driver = BasicHandshakeDriver<T>;

    fn new_initiator(&self, _server_name: &str, noise_handshake: &mut impl HandshakeInfo) -> Result<Self::Driver, Error> {
        noise_handshake.initialize(&mut OsRng, self.protocol, &[], self.s.as_ref().map(SecretKey::as_bytes).map(SecretKeySetup::from), self.rs.as_ref().map(PublicKey::as_ref))?;
        
        Ok(BasicHandshakeDriver {
            payload_driver: self.payload_driver.clone(),
        })
    }
    
    fn new_responder(&self, _preamble: &[u8], noise_handshake: &mut impl HandshakeInfo) -> Result<Self::Driver, Error> {
        noise_handshake.initialize(&mut OsRng, self.protocol, &[], self.s.as_ref().map(SecretKey::as_bytes).map(SecretKeySetup::from), self.rs.as_ref().map(PublicKey::as_ref))?;
        
        Ok(BasicHandshakeDriver {
            payload_driver: self.payload_driver.clone(),
        })
    }
}

pub struct BasicHandshakeDriver<T: PayloadDriver> {
    payload_driver: T,
}

impl<T: PayloadDriver> HandshakeDriver for BasicHandshakeDriver<T> {}

impl<T: PayloadDriver> PayloadDriver for BasicHandshakeDriver<T> {
    fn write_noise_payload(&mut self, payload_buffer: &mut impl Buffer, noise_handshake: &mut impl HandshakeInfo) -> Result<(), Error> {
        self.payload_driver.write_noise_payload(payload_buffer, noise_handshake)
    }

    fn read_noise_payload(&mut self, payload: &[u8], noise_handshake: &mut impl HandshakeInfo) -> Result<(), Error> {
        self.payload_driver.read_noise_payload(payload, noise_handshake)
    }
}

/// Default, no-payload driver.
/// 
/// Sends no application payloads and rejects any non-empty application
/// payloads.
#[derive(Clone)]
pub struct DefaultPayloadDriver;

impl PayloadDriver for DefaultPayloadDriver {
    fn write_noise_payload(&mut self, _buffer: &mut impl Buffer, _noise_handshake: &mut impl HandshakeInfo) -> Result<(), Error> {
        Ok(())
    }

    fn read_noise_payload(&mut self, buffer: &[u8], _noise_handshake: &mut impl HandshakeInfo) -> Result<(), Error> {
        match buffer.is_empty() {
            true => Ok(()),
            false => Err(Error::HandshakeFailed),
        }
    }
}
