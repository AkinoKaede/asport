use std::{env, net::UdpSocket, process};

use anyhow::Result;
use base64ct::Encoding;
use rand_core::OsRng;
use quinn::Endpoint;

use quinn_hyphae::{
    HandshakeBuilder,
    RustCryptoBackend,
    HyphaePeerIdentity,
    helper::{hyphae_client_endpoint, hyphae_server_endpoint}
};

const SERVER_ADDR: &'static str = "127.0.0.1:5777";
const CLIENT_ADDR: &'static str = "127.0.0.1:0";

#[tokio::main]
async fn main() -> Result<()> {
    let is_server = args_is_server();

    let secret_key = RustCryptoBackend.new_secret_key(&mut OsRng);
    let public_key = RustCryptoBackend.public_key(&secret_key);
    let public_key_b64 = base64ct::Base64::encode_string(&public_key);

    let noise_protocol = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

    let crypto_config = 
        HandshakeBuilder::new(noise_protocol)
        .with_static_key(&secret_key)
        .build(RustCryptoBackend)
        .unwrap();

    let socket = match is_server {
        true => UdpSocket::bind(SERVER_ADDR).unwrap(),
        false => UdpSocket::bind(CLIENT_ADDR).unwrap(),
    };

    println!("Endpoint on {:?} with public key {:?}", socket.local_addr().unwrap(), public_key_b64);

    if is_server {
        let endpoint = hyphae_server_endpoint(crypto_config, None, socket).unwrap();
        run_echo_server(endpoint).await?;

    } else {
        let endpoint = hyphae_client_endpoint(crypto_config, None, socket).unwrap();
        echo_client(endpoint, SERVER_ADDR, "hello quinn-hyphae!".into()).await?;
    }

    Ok(())
}

fn args_is_server() -> bool {
    let arg = env::args().skip(1).next();

    match &arg {
        Some(arg) if arg == "--server" => true,
        Some(arg) if arg == "--client" => false,
        _ => {
            eprintln!("Specify --server or --client");
            process::exit(-1);
        }
    }
}

async fn run_echo_server(endpoint: Endpoint) -> Result<()> {
    loop {
        let Some(incoming) = endpoint.accept().await else {
            break;
        };

        let join = tokio::spawn(async move {
            let conn = incoming.await?;

            let peer_addr = conn.remote_address();
            let peer_id = conn.peer_identity().unwrap().downcast::<HyphaePeerIdentity>().unwrap();
            println!("Connection from {peer_addr}");
            println!("Peer Identity: {:?}", peer_id);

            let (mut send_stream, mut recv_stream) = conn.accept_bi().await?;

            let echo_recv = recv_stream.read_to_end(100).await?;

            send_stream.write_all(&echo_recv).await?;
            send_stream.finish()?;
            send_stream.stopped().await?;

            println!("Echoed '{}'", String::from_utf8_lossy(&echo_recv));

            Ok::<_, anyhow::Error>(())
        });

        join.await??;
    }

    Ok(())
}

async fn echo_client(endpoint: Endpoint, server_addr: &str, echo: String) -> Result<()> {
    let conn = endpoint.connect(server_addr.parse().unwrap(), "")?.await?;

    let peer_id = conn.peer_identity().unwrap().downcast::<HyphaePeerIdentity>().unwrap();
    println!("Connected to {:?}", conn.remote_address());
    println!("  Peer Identity: {:?}", peer_id);

    let echo_bytes = echo.as_bytes();

    let (mut send_stream, mut recv_stream) = conn.open_bi().await?;
    send_stream.write_all(echo.as_bytes()).await?;
    send_stream.finish()?;
    send_stream.stopped().await?;
    println!("  Sent '{echo}'");

    let echo_recv = recv_stream.read_to_end(echo_bytes.len()).await?;
    println!("  Received '{}'", String::from_utf8_lossy(&echo_recv));
    
    Ok(())
}