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

Not available yet. If you can help to package this projects, I would be grateful.

### Manual

#### Download

Download the latest release from the [release page](https://github.com/AkinoKaede/asport/releases).

Here is the suggested target for common platforms:

| Operating System                                    | Architecture                | Target                     |
|-----------------------------------------------------|-----------------------------|----------------------------|
| Linux (most distros)                                | x86_64 (aka. x86-64, amd64) | x86_64-unknown-linux-gnu   |
| Linux (Alpine Linux, OpenWrt, and some old distros) | x86_64                      | x86_64-unknown-linux-musl  |
| Linux (most distros)                                | aarch64                     | aarch64-unknown-linux-gnu  |
| Linux (Alpine Linux, OpenWrt, and some old distros) | aarch64                     | aarch64-unknown-linux-musl |
| macOS                                               | x86_64 (Intel)              | x86_64-apple-darwin        |
| macOS                                               | aarch64 (Apple Silicon)     | aarch64-apple-darwin       |
| Windows                                             | x86_64                      | x86_64-pc-windows-msvc     |
| Windows                                             | aarch64                     | aarch64-pc-windows-msvc    |

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
cp asport-server /usr/local/bin
cp asport-client /usr/local/bin
```

## Configuration

### Server

You can copy the quick start configuration from the [client.quick.example.toml](./client.quick.example.toml).

If you want to learn more about the configuration, please refer to the [client.example.toml](./client.example.toml).

### Client

You can copy the quick start configuration from the [server.quick.example.toml](./server.quick.example.toml).

If you want to learn more about the configuration, please refer to the [server.example.toml](./server.example.toml).

## Run

```bash
# Run Server
asport-server -c server.toml

# Run Client
asport-client -c client.toml
```
