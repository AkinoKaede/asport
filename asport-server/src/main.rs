/*
* Asport, a quick and secure reverse proxy based on QUIC for NAT traversal.
* Copyright (C) 2024 Kaede Akino
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

use crate::server::Server;
use base64::{engine::general_purpose::STANDARD, Engine};
use clap::{Parser, Subcommand};
use env_logger::Builder as LoggerBuilder;
use quinn_hyphae::RustCryptoBackend;
use rand_core::OsRng;
use std::{cell::LazyCell, path::PathBuf, process};
use uuid::Uuid;

mod config;
mod connection;
mod error;
mod server;
mod utils;

#[derive(Parser)]
#[command(
    about = "Asport, a quick and secure reverse proxy based on QUIC for NAT traversal. asport-server is a simple Asport server implementation.",
    author,
    version
)]
struct Arguments {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    #[clap(about = "Run the Asport server")]
    Run {
        #[clap(short, long)]
        config: Option<PathBuf>,
    },
    #[clap(about = "Generate a new UUID")]
    Uuid,
    #[clap(about = "Generate a new X25519 key pair", alias = "curve25519")]
    X25519,
    #[clap(about = "Display the license information", alias = "copying")]
    License,
}

#[tokio::main]
async fn main() {
    let args = Arguments::parse();

    match args.command {
        Commands::Run { config } => {
            run(config).await;
        }
        Commands::Uuid => {
            uuid().await;
        }
        Commands::X25519 => {
            x25519().await;
        }
        Commands::License => {
            license().await;
        }
    }
}

async fn run(config: Option<PathBuf>) {
    let config_path = config.unwrap_or_else(|| {
        if let Some(path) = find_config() {
            path
        } else {
            eprintln!("No configuration file found, please specify one with --config");
            process::exit(1);
        }
    });

    let cfg = match config::Config::build(config_path) {
        Ok(cfg) => cfg,
        Err(err) => {
            eprintln!("{err}");
            process::exit(1);
        }
    };

    LoggerBuilder::new()
        .filter_level(cfg.log_level)
        .format_module_path(false)
        .format_target(false)
        .init();

    match Server::init(cfg) {
        Ok(server) => server.start().await,
        Err(err) => {
            eprintln!("{err}");
            process::exit(1);
        }
    }
}

async fn uuid() {
    let uuid = Uuid::new_v4();
    println!("{}", uuid);
}

async fn x25519() {
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

async fn license() {
    println!("Asport, a quick and secure reverse proxy based on QUIC for NAT traversal.");
    println!("Copyright (C) 2024 Kaede Akino");
    println!();
    println!("This program is free software: you can redistribute it and/or modify");
    println!("it under the terms of the GNU General Public License as published by");
    println!("the Free Software Foundation, either version 3 of the License, or");
    println!("(at your option) any later version.");
    println!();
    println!("This program is distributed in the hope that it will be useful,");
    println!("but WITHOUT ANY WARRANTY; without even the implied warranty of");
    println!("MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the");
    println!("GNU General Public License for more details.");
    println!();
    println!("You should have received a copy of the GNU General Public License");
    println!("along with this program. If not, see <http://www.gnu.org/licenses/>.");
}

const CONFIG_EXTENSIONS: [&str; 6] = ["json", "jsonc", "ron", "toml", "yaml", "yml"];
const CONFIG_NAMES: LazyCell<Vec<PathBuf>> = LazyCell::new(|| {
    CONFIG_EXTENSIONS
        .iter()
        .map(|ext| PathBuf::from(format!("server.{}", ext)))
        .collect::<Vec<_>>()
});

#[cfg(unix)]
fn find_config() -> Option<PathBuf> {
    for config in CONFIG_NAMES.iter() {
        if config.exists() {
            return Some(config.clone());
        }
    }

    let xdg_dirs = xdg::BaseDirectories::with_prefix("asport");

    for config in CONFIG_NAMES.iter() {
        if let Some(path) = xdg_dirs.find_config_file(config) {
            return Some(path);
        }
    }

    None
}

#[cfg(not(unix))]
fn find_config() -> Option<PathBuf> {
    for config in CONFIG_NAMES.iter() {
        if config.exists() {
            return Some(config.clone());
        }
    }

    None
}
