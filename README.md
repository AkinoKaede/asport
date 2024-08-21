# Asport

A quick and secure reverse proxy based on QUIC for NAT traversal.

## Introduction

Asport is a project that aims to provide an implementation for ASPORT. ASPORT is a reverse proxy protocol that uses QUIC
as its transport layer.

ASPORT is designed on the top of [QUIC](https://www.rfc-editor.org/rfc/rfc9000.html) protocol, which is a multiplexed,
secure, and reliable transport protocol.

When paired with QUIC, ASPORT can achieve:

- Fully multiplexed. All streams and datagrams are multiplexed in a single QUIC connection.
- Two UDP proxying modes:
    - `native`: Having characteristics of native UDP mechanism, transferring UDP packets lossy using QUIC unreliable datagram.
    - `quic`: Transferring UDP packets lossless using QUIC unidirectional streams.
- All the advantages of QUIC, including but not limited to:
    - Bidirectional user-space congestion control.
    - Optional 0-RTT connection handshake.
    - Connection migration.

The specification of ASPORT can be found in [SPEC.md](./SPEC.md).

## Features

Why should you choose Asport?

- Secure. ASPORT uses QUIC as its transport layer, which uses TLS 1.3 for encryption.
- Low latency. ASPORT uses QUIC's stream multiplexing to reduce the latency caused by the additional handshake.
- Higher transfer speed than traditional multiplexed TCP-based proxies. Many ISP limits the speed of a single TCP connection,
but QUIC can bypass this limitation.
- Awesome UDP forwarding. Many similar projects use stream-based connection to forward UDP packets (e.g. UDP over TCP), when
loss a packet, subsequent packets will be delayed. ASPORT uses QUIC's unidirectional stream and unreliable datagram to
forward UDP packets, which can avoid this problem.
- User-space congestion control. You can use BBR on any platform, even if the platform does not support it, such as macOS. 
- [PROXY protocol](https://www.haproxy.org/download/2.4/doc/proxy-protocol.txt) support in Client.
- Some simple censorship circumvention features. You can bypass some DPI and probing by setting some options in configuration.
You can bypass firewall in some companies, schools, and etc. (I don't encourage you to do this, but it's a feature.)
The design of it is based my experience in developing some anti-censorship software.

## Quick Start

Please refer to the [Quick Start](./QUICK_START.md) guide.

## Project Structure

This repository contains the following crates:

- **[asport](./asport)** - Library. The protocol itself, protocol & model abstraction, synchronous / asynchronous marshalling.
- **[asport-quinn](./asport-quinn)** - Library. A wrapper around [quinn](https://github.com/quinn-rs/quinn) to provide functions of ASPORT.
- **[asport-server](./asport-server)** - Binary. A simple ASPORT server implementation as a reference.
- **[asport-client](./asport-client)** - Binary. A simple ASPORT client implementation as a reference.

## Roadmap

- [ ] Better documentation.
- [ ] Mock tests.

### Long-term Goals

- [ ] REST/RPC interface for `asport-server`.
- [ ] Web status monitor for `asport-server`.
- [ ] Web console for `asport-server`.
- [ ] Full-featured implementation of ASPORT in Go.

## Credits

This project is highly inspired by [TUIC](https://github.com/EAimTY/tuic). Many ideas and code snippets are borrowed from
[TUIC](https://github.com/EAimTY/tuic). Thanks to the authors and contributors of TUIC for providing such a great project.

## License

This repository is licensed under [GNU General Public License v3.0 or later](./LICENSE).

SPDX-License-Identifier: [GPL-3.0-or-later](https://spdx.org/licenses/GPL-3.0-or-later.html)