//! The 'xk_handshake` example sets up two bidirectional endpoints
//! secured with a Noise XK handshake.
//! 
//! This kind of configuration may be useful for peer-to-peer
//! applications and shows how to use the `HandshakeBuilder's`
//! `with_server_name_as_remote_public()` functionality. This allows
//! the public key of the peer to be supplied as a Base64 string in the
//! `server_name` argument for outgoing connections.
//! 

use std::net::{SocketAddr, UdpSocket};

use anyhow::Result;
use base64ct::{Base64, Encoding as _};
use quinn::{Endpoint, VarInt};
use rand_core::OsRng;

use quinn_hyphae::{
    HandshakeBuilder,
    HyphaePeerIdentity,
    RustCryptoBackend,
    helper::hyphae_bidirectional_endpoint, 
};

#[tokio::main]
async fn main() -> Result<()> {

    let (endpoint_1, pubkey_1) = create_endpoint("Foo")?;
    let (endpoint_2, pubkey_2) = create_endpoint("Bar")?;

    let e1_task = tokio::spawn(accept_connection("Foo", endpoint_1.clone()));
    let e2_task = tokio::spawn(accept_connection("Bar", endpoint_2.clone()));

    let endpoint_1_addr = endpoint_1.local_addr()?;
    connect("Foo", endpoint_1, endpoint_2.local_addr()?, &pubkey_2).await?;
    connect("Bar", endpoint_2, endpoint_1_addr, &pubkey_1).await?;

    let (e1_res, e2_res) = tokio::try_join!(e1_task, e2_task)?;
    e1_res?;
    e2_res?;

    println!("Success!");
    Ok(())
}

fn create_endpoint(name: &str) -> Result<(Endpoint, String)> {
    let secret_key = RustCryptoBackend.new_secret_key(&mut OsRng);
    let public_key = Base64::encode_string(&RustCryptoBackend.public_key(&secret_key));

    let socket = UdpSocket::bind("127.0.0.1:0")?;

    let crypto_config =
        HandshakeBuilder::new("Noise_XK_25519_ChaChaPoly_BLAKE2s")
        .with_static_key(&secret_key)
        .with_server_name_as_remote_public()
        .build(RustCryptoBackend)?;

    let endpoint = hyphae_bidirectional_endpoint(crypto_config, None, socket)?;

    println!("{name}: Listening on {} as '{public_key}'", endpoint.local_addr()?);

    Ok((endpoint, public_key))
}

async fn connect(name: &str, endpoint: Endpoint, addr: SocketAddr, pubkey: &str) -> Result<()> {
    println!("{name}: Connecting to '{pubkey}'...");
    let conn = endpoint.connect(addr, pubkey)?.await?;
    conn.close(VarInt::from_u32(0), b"goodbye");
    Ok(())
}

async fn accept_connection(name: &str, endpoint: Endpoint) -> Result<()> {
    if let Some(incoming) = endpoint.accept().await {
        let conn = incoming.accept()?.await?;
        let id = conn.peer_identity().unwrap().downcast::<HyphaePeerIdentity>().unwrap();
        println!("{name}: Accepted connection from '{}'",  Base64::encode_string(&id.remote_public.unwrap()));
        conn.closed().await;
    }
    Ok(())
}
