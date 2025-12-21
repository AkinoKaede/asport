/*
* Asport, Asport, a quick and secure reverse tunnel based on QUIC.
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

use std::{path::PathBuf, process};

use crate::connection::Connection;
use asport_common::{cli, config_paths};
use clap::{Parser, Subcommand};
use env_logger::Builder as LoggerBuilder;

mod config;
mod connection;
mod error;
mod utils;

#[derive(Parser)]
#[command(
    about = "Asport, a quick and secure reverse proxy based on QUIC for NAT traversal. asport-client is a simple Asport client implementation.",
    author,
    version
)]
struct Arguments {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    #[clap(about = "Run the Asport client")]
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
        config_paths::find_config("client").unwrap_or_else(|| {
            eprintln!("No configuration file found, please specify one with --config");
            process::exit(1);
        })
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
    cli::print_uuid();
}

async fn x25519() {
    cli::print_x25519_keypair();
}

async fn license() {
    cli::print_license();
}
