# Quick Start

## Installation

### Cargo

#### Pre-requisite

You need to have [Rust](https://www.rust-lang.org/tools/install) installed on your system.

#### Install

```bash
# Install Server
cargo install asport-server

# Install Client
cargo install asport-client
```

### Package Manager

#### Homebrew

```bash
brew tap AkinoKaede/asport

# Install Server
brew install asport-server

# Install Client
brew install asport-client

# Start Server
brew services start asport-server

# Start Client
brew services start asport-client
```

### Nix

Because asport uses new features in Rust 1.80.0, but the Rust in latest Nix stable channel (24.05) is 1.77.2, so we cannot use Nix to install asport directly.

However, here is a [nix package](https://github.com/AkinoKaede/nur-packages/blob/master/pkgs/asport/default.nix) in my NUR as s reference.

### Manual

#### Download

Download the latest release from the [release page](https://github.com/AkinoKaede/asport/releases).

Here is the suggested target for common platforms:

| Operating System                                    | Architecture                | Target                     | Download                                                                                                           |
|-----------------------------------------------------|-----------------------------|----------------------------|--------------------------------------------------------------------------------------------------------------------|
| Linux (most distros)                                | x86_64 (aka. x86-64, amd64) | x86_64-unknown-linux-gnu   | [Download](https://github.com/AkinoKaede/asport/releases/latest/download/asport-x86_64-unknown-linux-gnu.tar.xz)   |
| Linux (Alpine Linux, OpenWrt, and some old distros) | x86_64                      | x86_64-unknown-linux-musl  | [Download](https://github.com/AkinoKaede/asport/releases/latest/download/asport-x86_64-unknown-linux-musl.tar.xz)  |
| Linux (most distros)                                | aarch64                     | aarch64-unknown-linux-gnu  | [Download](https://github.com/AkinoKaede/asport/releases/latest/download/asport-aarch64-unknown-linux-gnu.tar.xz)  |
| Linux (Alpine Linux, OpenWrt, and some old distros) | aarch64                     | aarch64-unknown-linux-musl | [Download](https://github.com/AkinoKaede/asport/releases/latest/download/asport-aarch64-unknown-linux-musl.tar.xz) |
| macOS                                               | x86_64 (Intel)              | x86_64-apple-darwin        | [Download](https://github.com/AkinoKaede/asport/releases/latest/download/asport-x86_64-apple-darwin.tar.xz)        |
| macOS                                               | aarch64 (Apple Silicon)     | aarch64-apple-darwin       | [Download](https://github.com/AkinoKaede/asport/releases/latest/download/asport-aarch64-apple-darwin.tar.xz)       |
| Windows                                             | x86_64                      | x86_64-pc-windows-msvc     | [Download](https://github.com/AkinoKaede/asport/releases/latest/download/asport-x86_64-pc-windows-msvc.zip)        |
| Windows                                             | aarch64                     | aarch64-pc-windows-msvc    | [Download](https://github.com/AkinoKaede/asport/releases/latest/download/asport-aarch64-pc-windows-msvc.zip)       |

Your target may vary, please check
the [Rust Platform Support](https://doc.rust-lang.org/nightly/rustc/platform-support.html) for more information.

### Extract

On Linux and macOS, you can extract the tarball with the following command:

```bash
tar -xvf asport-*.tar.xz
```

On Windows, you can extract the zip file with the following command:

```powershell
tar -xvf asport-*.zip
```

You can also use a graphical tool to extract the archive, such as built-in File Explorer on Windows, Finder on
macOS, or any third-party tools like 7-Zip.

### Install

After extracting the archive on Linux and macOS, you can install the binaries to your system with the following command:

```bash
sudo install -m 755 asport-server /usr/local/bin
sudo install -m 755 asport-client /usr/local/bin
```

On Linux distros that use systemd as its init system, you can also install the systemd service files with the following
command:

```bash
sudo install -m 644 systemd/system.asport-server.service /etc/systemd/system/asport-server.service
sudo install -m 644 systemd/system.asport-server@.service /etc/systemd/system/asport-server@.service 
sudo install -m 644 systemd/system.asport-client.service /etc/systemd/system/asport-client.service
sudo install -m 644 systemd/system.asport-client@.service /etc/systemd/system/asport-client@.service
```

## Configuration

### Server

You can copy the quick start configuration from the [server.quick.example.toml](./server.quick.example.toml).

If you want to learn more about the configuration, please refer to the [server.example.toml](./server.example.toml).

### Client

You can copy the quick start configuration from the [client.quick.example.toml](./client.quick.example.toml).

If you want to learn more about the configuration, please refer to the [client.example.toml](./client.example.toml).

## Run

```bash
# Run Server
asport-server run -c server.toml

# Run Client
asport-client run -c client.toml
```

On Linux distros that use systemd as its init system, you can also start the server and client with the following
command:

In addition, you should put your configuration files in `/usr/local/etc/asport/`.

```bash
# Run Server with default configuration file (server.toml)
sudo systemctl start asport-server

# Run Server with a specific configuration file
sudo systemctl start asport-server@server.yml

# Run Client  with default configuration file (client.toml)
sudo systemctl start asport-client

# Run Server with a specific configuration file
sudo systemctl start asport-server@client.json
```