//! Example demonstrating export_keying_material functionality
//! 
//! This example shows how to use Hyphae's export_keying_material feature,
//! which is similar to TLS's export_keying_material function.

use std::net::UdpSocket;
use anyhow::Result;
use rand_core::OsRng;
use quinn_hyphae::{
    HandshakeBuilder,
    RustCryptoBackend,
    helper::{hyphae_client_endpoint, hyphae_server_endpoint}
};

const SERVER_ADDR: &str = "127.0.0.1:5778";
const CLIENT_ADDR: &str = "127.0.0.1:0";

#[tokio::main]
async fn main() -> Result<()> {
    // Setup server
    let server_secret = RustCryptoBackend.new_secret_key(&mut OsRng);
    let server_crypto_config = 
        HandshakeBuilder::new("Noise_XX_25519_ChaChaPoly_BLAKE2s")
        .with_static_key(&server_secret)
        .build(RustCryptoBackend)?;
    
    let server_socket = UdpSocket::bind(SERVER_ADDR)?;
    let server_endpoint = hyphae_server_endpoint(server_crypto_config, None, server_socket)?;

    // Setup client  
    let client_secret = RustCryptoBackend.new_secret_key(&mut OsRng);
    let client_crypto_config =
        HandshakeBuilder::new("Noise_XX_25519_ChaChaPoly_BLAKE2s")
        .with_static_key(&client_secret)
        .build(RustCryptoBackend)?;
    
    let client_socket = UdpSocket::bind(CLIENT_ADDR)?;
    let client_endpoint = hyphae_client_endpoint(client_crypto_config, None, client_socket)?;

    // Store server keys for comparison
    let mut server_auth_key = vec![0u8; 32];
    let mut server_channel_binding = vec![0u8; 16];
    let mut server_metadata_key = vec![0u8; 32];
    let mut server_pop_key = vec![0u8; 64];

    // Start server task
    let server_task = tokio::spawn(async move {
        if let Some(incoming) = server_endpoint.accept().await {
            let conn = incoming.await?;
            println!("Server: Connection established");

            // Export application keys after handshake completion
            // This demonstrates various use cases for export_keying_material
            
            // 1. Application-layer authentication key
            conn.export_keying_material(&mut server_auth_key, b"app-auth-v1", b"")
                .map_err(|e| anyhow::anyhow!("Server export_keying_material failed: {:?}", e))?;
            println!("Server: App authentication key: {:02x?}", &server_auth_key[..8]);

            // 2. Channel binding for additional security
            conn.export_keying_material(
                &mut server_channel_binding,
                b"channel-binding", 
                b"unique-session-identifier"
            ).map_err(|e| anyhow::anyhow!("Server channel binding export failed: {:?}", e))?;
            println!("Server: Channel binding: {:02x?}", &server_channel_binding);

            // 3. Key for encrypting application metadata
            conn.export_keying_material(&mut server_metadata_key, b"metadata-encryption", b"")
                .map_err(|e| anyhow::anyhow!("Server metadata key export failed: {:?}", e))?;
            println!("Server: Metadata key: {:02x?}", &server_metadata_key[..8]);

            // 4. Proof-of-possession key for external protocol
            // Use a deterministic session context based on handshake hash
            let session_context = b"session-example-context";
            conn.export_keying_material(
                &mut server_pop_key,
                b"proof-of-possession",
                session_context
            ).map_err(|e| anyhow::anyhow!("Server PoP key export failed: {:?}", e))?;
            println!("Server: Proof-of-possession key: {:02x?}", &server_pop_key[..8]);

            Ok::<_, anyhow::Error>((server_auth_key, server_channel_binding, server_metadata_key, server_pop_key))
        } else {
            Err(anyhow::anyhow!("No incoming connection"))
        }
    });

    // Connect from client
    let client_conn = client_endpoint.connect(SERVER_ADDR.parse()?, "")?.await?;
    println!("Client: Connection established");

    // Export the same keys on client side - they should match!
    let mut client_auth_key = vec![0u8; 32];
    client_conn.export_keying_material(&mut client_auth_key, b"app-auth-v1", b"")
        .map_err(|e| anyhow::anyhow!("Client auth key export failed: {:?}", e))?;
    println!("Client: App authentication key: {:02x?}", &client_auth_key[..8]);

    let mut client_channel_binding = vec![0u8; 16];
    client_conn.export_keying_material(
        &mut client_channel_binding,
        b"channel-binding",
        b"unique-session-identifier"
    ).map_err(|e| anyhow::anyhow!("Client channel binding export failed: {:?}", e))?;
    println!("Client: Channel binding: {:02x?}", &client_channel_binding);

    let mut client_metadata_key = vec![0u8; 32];
    client_conn.export_keying_material(&mut client_metadata_key, b"metadata-encryption", b"")
        .map_err(|e| anyhow::anyhow!("Client metadata key export failed: {:?}", e))?;
    println!("Client: Metadata key: {:02x?}", &client_metadata_key[..8]);

    // Use the same session context as server
    let session_context = b"session-example-context";
    let mut client_pop_key = vec![0u8; 64];
    client_conn.export_keying_material(
        &mut client_pop_key,
        b"proof-of-possession",
        session_context
    ).map_err(|e| anyhow::anyhow!("Client PoP key export failed: {:?}", e))?;
    println!("Client: Proof-of-possession key: {:02x?}", &client_pop_key[..8]);

    // Wait for server to complete and get server keys
    let (server_auth_key, server_channel_binding, server_metadata_key, server_pop_key) = server_task.await??;

    // Verify that both sides derived the same keys
    // This is important for security - both peers must derive identical keys
    // for the same (label, context) pair
    println!("\n--- Key Verification ---");
    println!("Auth keys match: {}", client_auth_key == server_auth_key);
    println!("Channel bindings match: {}", client_channel_binding == server_channel_binding);
    println!("Metadata keys match: {}", client_metadata_key == server_metadata_key);
    println!("PoP keys match: {}", client_pop_key == server_pop_key);

    // Example of different labels producing different keys
    let mut key1 = vec![0u8; 32];
    let mut key2 = vec![0u8; 32];
    client_conn.export_keying_material(&mut key1, b"label1", b"")
        .map_err(|e| anyhow::anyhow!("Key1 export failed: {:?}", e))?;
    client_conn.export_keying_material(&mut key2, b"label2", b"")
        .map_err(|e| anyhow::anyhow!("Key2 export failed: {:?}", e))?;
    println!("Different labels produce different keys: {}", key1 != key2);

    // Example of different contexts producing different keys
    let mut ctx_key1 = vec![0u8; 32];
    let mut ctx_key2 = vec![0u8; 32];
    client_conn.export_keying_material(&mut ctx_key1, b"same-label", b"context1")
        .map_err(|e| anyhow::anyhow!("Context key1 export failed: {:?}", e))?;
    client_conn.export_keying_material(&mut ctx_key2, b"same-label", b"context2")
        .map_err(|e| anyhow::anyhow!("Context key2 export failed: {:?}", e))?;
    println!("Different contexts produce different keys: {}", ctx_key1 != ctx_key2);

    println!("\nSuccess! export_keying_material working correctly.");
    Ok(())
}