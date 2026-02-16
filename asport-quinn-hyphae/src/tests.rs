use std::{net::UdpSocket, sync::Arc};

use hyphae_handshake::crypto::SyncCryptoBackend;
use hyphae_handshake::{customization::SyncHandshakeConfig, quic::HYPHAE_H_V1_QUIC_V1_VERSION};
use quinn_proto::{crypto::ServerConfig as CryptoServerConfig, transport_parameters::TransportParameters, ConnectionId, Side};
use rand_core::OsRng;

use crate::RustCryptoBackend;
use crate::HandshakeBuilder;
use crate::helper::{hyphae_client_endpoint, hyphae_server_endpoint};
use crate::{config::HyphaeCryptoConfig, customization::{HyphaePeerIdentity, QuinnHandshakeData}};

#[tokio::test]
async fn quinn_echo_test() {
    quinn_echo_test_proto("Noise_XX_25519_ChaChaPoly_BLAKE2s").await;
    quinn_echo_test_proto("Noise_XX_25519_ChaChaPoly_BLAKE2b").await;
    quinn_echo_test_proto("Noise_XX_25519_ChaChaPoly_SHA256").await;
    quinn_echo_test_proto("Noise_XX_25519_ChaChaPoly_SHA512").await;
    quinn_echo_test_proto("Noise_XX_25519_AESGCM_BLAKE2s").await;
    quinn_echo_test_proto("Noise_XX_25519_AESGCM_BLAKE2b").await;
    quinn_echo_test_proto("Noise_XX_25519_AESGCM_SHA256").await;
    quinn_echo_test_proto("Noise_XX_25519_AESGCM_SHA512").await;
}

async fn quinn_echo_test_proto(protocol: &str) {
    let initiator_s = RustCryptoBackend.new_secret_key(&mut OsRng);
    let client_crypto = 
        HandshakeBuilder::new(protocol)
        .with_static_key(&initiator_s)
        .build(RustCryptoBackend)
        .unwrap();
    
    let responder_s = RustCryptoBackend.new_secret_key(&mut OsRng);
    let server_crypto = 
        HandshakeBuilder::new(protocol)
        .with_static_key(&responder_s)
        .build(RustCryptoBackend)
        .unwrap();

    echo_server_test(
        client_crypto,
        server_crypto,
        Some(RustCryptoBackend.public_key(&initiator_s).to_vec()), 
        Some(RustCryptoBackend.public_key(&responder_s).to_vec())
    ).await;
}

async fn echo_server_test<IC, IB, RC, RB> (
    client_crypto: Arc<HyphaeCryptoConfig<IC, IB>>,
    server_crypto: Arc<HyphaeCryptoConfig<RC, RB>>,
    client_public: Option<Vec<u8>>,
    server_public: Option<Vec<u8>>,
)
where 
    IC: SyncHandshakeConfig,
    IC::Driver: QuinnHandshakeData,
    IB: SyncCryptoBackend,
    RC: SyncHandshakeConfig,
    RC::Driver: QuinnHandshakeData,
    RB: SyncCryptoBackend,
{
    let listen_addr = "[0::1]:0";
    let echo_payload = b"hello hyphae-h-v1.quic-v1.";

    let socket = UdpSocket::bind(listen_addr).unwrap();
    let server_endpoint = hyphae_server_endpoint(server_crypto, None, socket).unwrap();
    let server_addr = server_endpoint.local_addr().unwrap();

    let server_task = async move {
        let conn = server_endpoint.accept().await.unwrap().await.unwrap();
        let handshake_rs = conn.peer_identity().unwrap().downcast::<HyphaePeerIdentity>().unwrap().remote_public;

        let mut recv = conn.accept_uni().await.unwrap();

        let mut buffer = vec![0u8; echo_payload.len()];
        recv.read_exact(&mut buffer).await.unwrap();
        assert_eq!(&buffer, echo_payload);

        handshake_rs
    };

    let client_task = async move {
        let socket = UdpSocket::bind(listen_addr).unwrap();
        let endpoint = hyphae_client_endpoint(client_crypto, None, socket).unwrap();

        let conn = endpoint.connect(server_addr, "").unwrap().await.unwrap();
        let handshake_rs = conn.peer_identity().unwrap().downcast::<HyphaePeerIdentity>().unwrap().remote_public;

        let mut send = conn.open_uni().await.unwrap();
        send.write_all(echo_payload).await.unwrap();
        send.finish().unwrap();
        send.stopped().await.unwrap();

        handshake_rs
    };

    let (client_handshake_rs, server_handshake_rs) = tokio::join!(client_task, server_task);
    assert_eq!(client_handshake_rs, server_public, "server had unexpected public key");
    assert_eq!(server_handshake_rs, client_public, "client had unexpected public key");
}

#[test]
fn retry_tag_test() {
    let protocol = "Noise_NN_25519_ChaChaPoly_BLAKE2s";
    let config = HandshakeBuilder::new(protocol).build(RustCryptoBackend).unwrap();

    let orig_dcid = ConnectionId::new(b"12345");
    let retry_packet_no_tag = b"abcdefg";

    let tag = config.retry_tag(HYPHAE_H_V1_QUIC_V1_VERSION, &orig_dcid, retry_packet_no_tag);
    
    let mut retry_packet_with_tag = Vec::new();
    retry_packet_with_tag.extend_from_slice(retry_packet_no_tag);
    retry_packet_with_tag.extend_from_slice(&tag);

    let start_session = CryptoServerConfig::start_session(config.clone(), HYPHAE_H_V1_QUIC_V1_VERSION, &fake_server_params());
    let session = start_session;
    assert!(session.is_valid_retry(&orig_dcid, &retry_packet_with_tag[0..2], &retry_packet_with_tag[2..]));
    retry_packet_with_tag[0] = !retry_packet_with_tag[0];
    assert!(!session.is_valid_retry(&orig_dcid, &retry_packet_with_tag[0..2], &retry_packet_with_tag[2..]));
}

fn fake_server_params() -> TransportParameters {
    let params = [
        1u8, 4, 128, 0, 117, 48, 3, 2, 69, 192, 4, 8, 255, 255, 255,
        255, 255, 255, 255, 255, 5, 4, 128, 19, 18, 208, 6, 4, 128,
        19, 18, 208, 7, 4, 128, 19, 18, 208, 8, 2, 64, 100, 9, 2,
        64, 100, 14, 1, 5, 64, 182, 0, 32, 4, 128, 0, 255, 255, 15,
        8, 107, 252, 186, 239, 84, 56, 32, 254, 106, 178, 0, 192, 0,
        0, 0, 255, 4, 222, 27, 2, 67, 232
    ];

    TransportParameters::read(Side::Server, &mut params.as_slice()).unwrap()
}
