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

use std::{cell::LazyCell, path::PathBuf, process};

use crate::connection::Connection;
use base64::{engine::general_purpose::STANDARD, Engine};
use clap::{Parser, Subcommand};
use env_logger::Builder as LoggerBuilder;
use quinn_hyphae::RustCryptoBackend;
use rand_core::OsRng;
use uuid::Uuid;

mod config;
mod connection;
mod error;
mod utils;

#[derive(Parser)]
#[command(about, author, version)]
struct Arguments {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Run {
        #[clap(short, long)]
        config: Option<PathBuf>,
    },
    Uuid,
    X25519,
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

    match Connection::set_config(cfg) {
        Ok(()) => {}
        Err(err) => {
            eprintln!("{err}");
            process::exit(1);
        }
    }

    Connection::start().await;
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

const CONFIG_EXTENSIONS: [&str; 6] = ["json", "jsonc", "ron", "toml", "yaml", "yml"];
const CONFIG_NAMES: LazyCell<Vec<PathBuf>> = LazyCell::new(|| {
    CONFIG_EXTENSIONS
        .iter()
        .map(|ext| PathBuf::from(format!("client.{}", ext)))
        .collect::<Vec<_>>()
});

#[cfg(unix)]
fn find_config() -> Option<PathBuf> {
    for config in CONFIG_NAMES.iter() {
        if config.exists() {
            return Some(config.clone());
        }
    }

    let xdg_dirs = if let Ok(xdg_dirs) = xdg::BaseDirectories::with_prefix("asport") {
        xdg_dirs
    } else {
        return None;
    };

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
