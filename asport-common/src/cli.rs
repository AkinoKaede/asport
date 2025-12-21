use base64::{engine::general_purpose::STANDARD, Engine};
use quinn_hyphae::RustCryptoBackend;
use rand_core::OsRng;
use uuid::Uuid;

/// Print a freshly generated UUID v4 to stdout.
pub fn print_uuid() {
    println!("{}", Uuid::new_v4());
}

/// Generate a new X25519 key pair and print both keys encoded as base64.
pub fn print_x25519_keypair() {
    let private_key = RustCryptoBackend.new_secret_key(&mut OsRng);
    let public_key = RustCryptoBackend.public_key(&private_key);

    let private_key_b64 = STANDARD.encode(private_key.as_ref());
    let public_key_b64 = STANDARD.encode(public_key.as_ref());

    println!("Private Key:");
    println!("{}", private_key_b64);
    println!();
    println!("Public Key:");
    println!("{}", public_key_b64);
}

/// Display the project license boilerplate text.
pub fn print_license() {
    for line in LICENSE_LINES {
        if line.is_empty() {
            println!();
        } else {
            println!("{}", line);
        }
    }
}

const LICENSE_LINES: &[&str] = &[
    "Asport, a quick and secure reverse proxy based on QUIC for NAT traversal.",
    "Copyright (C) 2024 Kaede Akino",
    "",
    "This program is free software: you can redistribute it and/or modify",
    "it under the terms of the GNU General Public License as published by",
    "the Free Software Foundation, either version 3 of the License, or",
    "(at your option) any later version.",
    "",
    "This program is distributed in the hope that it will be useful,",
    "but WITHOUT ANY WARRANTY; without even the implied warranty of",
    "MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the",
    "GNU General Public License for more details.",
    "",
    "You should have received a copy of the GNU General Public License",
    "along with this program. If not, see <http://www.gnu.org/licenses/>.",
];
