use crate::{Error, crypto::{CryptoBackend, SymmetricKey}, customization::HandshakeConfig, handshake::{AllocHyphaeHandshake, HandshakeVersion}};

const HARNESS_TRANSPORT_LABEL: &[u8] = b"harness";

pub fn alloc_handshake_harness<I, IB, R, RB> (
    init_handshake_config: &I,
    init_crypto: IB,
    resp_handshake_config: &R,
    resp_crypto: RB,
    server_name: &str,
) -> Result<(), Error>
where
    I: HandshakeConfig,
    IB: CryptoBackend,
    R: HandshakeConfig,
    RB: CryptoBackend,
{
    let mut buffer = Vec::new();

    let init_params = b"init_transport_params";
    let resp_params = b"resp_transport_params";

    let mut init_handshake = AllocHyphaeHandshake::new_initiator(init_handshake_config, &init_crypto, HandshakeVersion::Version1, HARNESS_TRANSPORT_LABEL, init_params.to_vec(), server_name)?;
    init_handshake.write_message(&mut buffer)?;

    let mut resp_handshake = AllocHyphaeHandshake::new_responder(resp_handshake_config, &resp_crypto, HandshakeVersion::Version1, HARNESS_TRANSPORT_LABEL, resp_params.to_vec(), buffer)?;

    loop {
        if init_handshake.is_handshake_finalized() {
            break;
        }

        if let Some(peer_params) = init_handshake.peer_params() {
            if peer_params != resp_params {
                return Err(Error::Internal);
            }
        }
        if let Some(peer_params) = resp_handshake.peer_params() {
            if peer_params != init_params {
                return Err(Error::Internal);
            }
        }

        let mut buffer = Vec::new();
        init_handshake.write_message(&mut buffer)?;
        if !buffer.is_empty() {
            resp_handshake.read_message(buffer)?;
        } else {
            resp_handshake.write_message(&mut buffer)?;
            if buffer.is_empty() {
                return Err(Error::Internal) // Deadlock
            }
            init_handshake.read_message(buffer)?;
        }

        let mut key = SymmetricKey::default();
        if init_handshake.next_level_secret_ready() {
            init_handshake.next_level_secret(&mut key)?;
        }
        if resp_handshake.next_level_secret_ready() {
            resp_handshake.next_level_secret(&mut key)?;
        }
    }

    if !resp_handshake.is_handshake_finalized() {
        return Err(Error::Internal)
    }

    if init_handshake.peer_params().is_none() || resp_handshake.peer_params().is_none() {
        return Err(Error::Internal)
    }

    Ok(())
}

#[cfg(test)]
pub mod tests {
    use std::{cell::RefCell, rc::Rc};

    use rand_core::OsRng;

    use crate::{buffer::Buffer, builder::HandshakeBuilder, crypto::{backends::rustcrypto::RustCryptoBackend, noise::patterns::HandshakePattern, SecretKeySetup}, customization::{HandshakeConfig, HandshakeDriver, HandshakeInfo, PayloadDriver}, Error};

    use super::alloc_handshake_harness;

    #[derive(Clone)]
    enum TestCase {
        EmptyPayloads,
        ClearPayloadBuffers,
        ClearPayloadWriteBadFrame,
        TooLargePayload,
    }

    #[derive(Default, Debug)]
    struct TestProgressTracker {
        init_s_public: Option<Vec<u8>>,
        resp_s_public: Option<Vec<u8>>,
        init_wrote_preamble: bool,
        init_payloads: u8,
        resp_payloads: u8,
        handshake_finished: bool,
        init_message_hashes: Vec<Vec<u8>>,
        resp_message_hashes: Vec<Vec<u8>>,
        init_final_hash: Option<Vec<u8>>,
        resp_final_hash: Option<Vec<u8>>,
        init_recv_final: bool,
        resp_recv_final: bool,
        rs_from_resp: Option<Vec<u8>>,
        rs_from_init: Option<Vec<u8>>,
    }

    impl TestProgressTracker {
        pub fn new() -> Rc<RefCell<Self>> {
            Default::default()
        }

        pub fn wrote_preamble(&mut self) {
            if self.init_wrote_preamble {
                panic!("preamble double write");
            }
            self.init_wrote_preamble = true;
        }

        pub fn noise_payload(&mut self, initiator: bool, position: u8, handshake_finished: bool, prev_hash: &[u8], rs: Option<&[u8]>) {
            if self.handshake_finished {
                panic!("handshake finished for more than one noise payload")
            }

            let (last_pos, hashes, rs_exp) = match initiator {
                true => (&mut self.init_payloads, &mut self.init_message_hashes, &mut self.rs_from_resp),
                false => (&mut self.resp_payloads, &mut self.resp_message_hashes, &mut self.rs_from_init),
            };

            if *last_pos + 1 != position {
                panic!("unexpected noise message, initiator: {initiator}, last_pos {last_pos}, pos: {position}");
            }
            *last_pos = position;

            hashes.push(prev_hash.to_vec());

            if rs_exp.is_none() {
                *rs_exp = rs.map(Vec::from);
            } else {
                if rs_exp.as_ref().map(Vec::as_slice) != rs {
                    panic!("rs changed mid-handshake")
                }
            }
            
            self.handshake_finished = handshake_finished;
        }

        pub fn recv_final_payload(&mut self, initiator: bool, final_hash: &[u8], rs: Option<&[u8]>) {
            let (done, side_final_hash, rs_exp) = match initiator {
                true => (&mut self.init_recv_final, &mut self.init_final_hash, &mut self.rs_from_resp),
                false => (&mut self.resp_recv_final, &mut self.resp_final_hash, &mut self.rs_from_init),
            };
            if *done {
                panic!("double recv finale, initiator: {initiator}");
            }

            if rs_exp.is_none() {
                *rs_exp = rs.map(Vec::from);
            } else {
                if rs_exp.as_ref().map(Vec::as_slice) != rs {
                    panic!("rs changed mid-handshake")
                }
            }
            
            *done = true;
            *side_final_hash = Some(final_hash.to_vec());
        }

        pub fn assert_finished(&self, expected_payloads: u8) {
            assert!(self.init_wrote_preamble);
            assert_eq!(self.init_payloads, expected_payloads);
            assert_eq!(self.resp_payloads, expected_payloads);
            assert!(self.init_recv_final);
            assert!(self.resp_recv_final);
            assert!(self.init_final_hash.is_some());
            assert_eq!(self.init_final_hash, self.resp_final_hash);
            assert_eq!(self.init_message_hashes, self.resp_message_hashes);
            assert!(self.handshake_finished);
            assert_eq!(self.init_s_public, self.rs_from_init);
            assert_eq!(self.resp_s_public, self.rs_from_resp);
        }
    }

    #[derive(Clone)]
    struct TestHandshakeConfig {
        test: TestCase,
        handshake: HandshakePattern,
        tracker: Rc<RefCell<TestProgressTracker>>,
    }

    impl TestHandshakeConfig {
        fn protocol(&self) -> String {
            format!("Noise_{}_25519_ChaChaPoly_BLAKE2s", self.handshake.name())
        }

        fn prologue(&self) -> &'static [u8] {
            b"test_prologue"
        }
    }

    impl HandshakeConfig for TestHandshakeConfig {
        type Driver = TestHandshakeDriver;

        fn initiator_preamble(&self, preamble_buffer: &mut impl Buffer) -> Result<(), Error> {
            self.tracker.borrow_mut().wrote_preamble();

            match self.test {
                TestCase::ClearPayloadBuffers => preamble_buffer.clear(),
                TestCase::ClearPayloadWriteBadFrame => {
                    preamble_buffer.clear();
                    preamble_buffer.push(0x50)?;
                },
                _ => {}
            }
            Ok(())
        }
    
        fn new_initiator(&self, _server_name: &str, noise_handshake: &mut impl HandshakeInfo) -> Result<Self::Driver, Error> {
            let s_secret = RustCryptoBackend.new_secret_key(&mut OsRng);
            let s_public = RustCryptoBackend.public_key(&s_secret);
            let s = match self.handshake {
                HandshakePattern::XX => {
                    self.tracker.borrow_mut().init_s_public = Some(s_public.to_vec());
                    Some(SecretKeySetup::Local(&s_secret))
                },
                _ => None,
            };
            noise_handshake.initialize(&mut OsRng, &self.protocol(), self.prologue(), s, None)?;

            Ok(TestHandshakeDriver {
                test: self.test.clone(),
                tracker: self.tracker.clone(),
            })
        }
    
        fn new_responder(&self, preamble: &[u8], noise_handshake: &mut impl HandshakeInfo) -> Result<Self::Driver, Error> {
            match self.test {
                TestCase::ClearPayloadWriteBadFrame => {
                    if preamble != b"\x50" {
                        panic!();
                    }
                },
                _ => {
                    if !preamble.is_empty() {
                        panic!();
                    }
                },
            }
            
            let s_secret = RustCryptoBackend.new_secret_key(&mut OsRng);
            let s_public = RustCryptoBackend.public_key(&s_secret);
            let s = match self.handshake {
                HandshakePattern::XX => {
                    self.tracker.borrow_mut().resp_s_public = Some(s_public.to_vec());
                    Some(SecretKeySetup::Local(&s_secret))
                },
                _ => None,
            };

            noise_handshake.initialize(&mut OsRng, &self.protocol(), self.prologue(), s, None)?;

            Ok(TestHandshakeDriver {
                test: self.test.clone(),
                tracker: self.tracker.clone(),
            })
        }
    }

    struct TestHandshakeDriver {
        test: TestCase,
        tracker: Rc<RefCell<TestProgressTracker>>,
    }

    impl HandshakeDriver for TestHandshakeDriver {
        fn write_final_payload(&mut self, payload_buffer: &mut impl Buffer, _noise_handshake: &mut impl HandshakeInfo) -> Result<(), Error> {
            match self.test {
                TestCase::ClearPayloadBuffers => payload_buffer.clear(),
                TestCase::ClearPayloadWriteBadFrame => {
                    payload_buffer.clear();
                    payload_buffer.push(0x50)?;
                },
                _ => {}
            }

            Ok(())
        }
    
        fn read_final_payload(&mut self, payload: &[u8], noise_handshake: &mut impl HandshakeInfo) -> Result<(), Error> {
            self.tracker.borrow_mut().recv_final_payload(noise_handshake.is_initiator(), noise_handshake.final_handshake_hash().unwrap(), noise_handshake.remote_public());

            match self.test {
                TestCase::ClearPayloadWriteBadFrame => {
                    if payload != b"\x50" {
                        panic!();
                    }
                },
                _ => {
                    if !payload.is_empty() {
                        panic!();
                    }
                }
            }

            Ok(())
        }
    }

    impl PayloadDriver for TestHandshakeDriver {
        fn write_noise_payload(&mut self, payload_buffer: &mut impl Buffer, noise_handshake: &mut impl HandshakeInfo) -> Result<(), Error> {
            self.tracker.borrow_mut().noise_payload(
                noise_handshake.is_initiator(), 
                noise_handshake.handshake_position().unwrap(), 
                noise_handshake.is_finished(), 
                noise_handshake.prev_handshake_hash().unwrap(),
                noise_handshake.remote_public()
            );

            match self.test {
                TestCase::ClearPayloadBuffers => payload_buffer.clear(),
                TestCase::ClearPayloadWriteBadFrame => {
                    payload_buffer.clear();
                    payload_buffer.push(0x50)?;
                },
                TestCase::TooLargePayload => {
                    for _ in 0..65 {
                        payload_buffer.extend_from_slice(&[1u8; 1024])?;
                    }
                },
                _ => {},
            }

            Ok(())
        }
    
        fn read_noise_payload(&mut self, payload: &[u8], noise_handshake: &mut impl HandshakeInfo) -> Result<(), Error> {
            self.tracker.borrow_mut().noise_payload(
                noise_handshake.is_initiator(), 
                noise_handshake.handshake_position().unwrap(), 
                noise_handshake.is_finished(), 
                noise_handshake.prev_handshake_hash().unwrap(),
                noise_handshake.remote_public()
            );

            match self.test {
                TestCase::ClearPayloadWriteBadFrame => {
                    if payload != b"\x50" {
                        panic!();
                    }
                },
                TestCase::TooLargePayload => {},
                _ => {
                    if !payload.is_empty() {
                        panic!();
                    }
                }
            }

            Ok(())
        }
    }

    fn test_handshake(test: TestCase, pattern: HandshakePattern) -> Result<(), Error> {
        let tracker = TestProgressTracker::new();
        let handshake_config = TestHandshakeConfig {
            test,
            handshake: pattern,
            tracker: tracker.clone(),
        };

        let res = alloc_handshake_harness(&handshake_config, RustCryptoBackend, &handshake_config, RustCryptoBackend, "");
        if res.is_ok() {
            let expected_payloads = match pattern {
                HandshakePattern::NN => 2,
                HandshakePattern::XX => 3,
                _ => unreachable!(),
            };
            tracker.borrow().assert_finished(expected_payloads);
        }
        res
    }

    #[test]
    fn handshake_customization_alloc() {
        // Only need to test patterns with different numbers of messages here.
        let patterns = &[/*HandshakePattern::NN,*/ HandshakePattern::XX];

        for pattern in patterns.iter().copied() {
            test_handshake(TestCase::EmptyPayloads, pattern).expect(&format!("EmptyPayloads with {}", pattern.name()));
            test_handshake(TestCase::ClearPayloadBuffers, pattern).expect(&format!("ClearPayloadBuffers with {}", pattern.name()));
            test_handshake(TestCase::ClearPayloadWriteBadFrame, pattern).expect(&format!("ClearPayloadWriteBadFrame with {}", pattern.name()));
            assert!(test_handshake(TestCase::TooLargePayload, pattern).is_err());
        }
    }

    #[test]
    fn handshake_harness_alloc() {
        let init_handshake_config = HandshakeBuilder::new("Noise_NN_25519_ChaChaPoly_BLAKE2s").build().unwrap();
        let resp_handshake_config = HandshakeBuilder::new("Noise_NN_25519_ChaChaPoly_BLAKE2s").build().unwrap();
        alloc_handshake_harness(&init_handshake_config, RustCryptoBackend, &resp_handshake_config, RustCryptoBackend, "").unwrap();
    }
}
