# asport

An implementation of ASPORT protocol.

[![Version](https://img.shields.io/crates/v/asport.svg?style=flat)](https://crates.io/crates/asport)
[![Documentation](https://img.shields.io/badge/docs-release-brightgreen.svg?style=flat)](https://docs.rs/asport)
[![License](https://img.shields.io/crates/l/asport.svg?style=flat)](https://github.com/AkinoKaede/asport/blob/main/LICENSE)

## Overview

The ASPORT protocol specification can be found in [SPEC.md](https://github.com/AkinoKaede/asport/blob/main/SPEC.md). This crate provides an implementation of the ASPORT protocol in Rust as a reference.

Here is a list of optional features that can be enabled:

- `model` - Provides a connection model abstraction of the ASPORT protocol, with packet fragmentation and task counter built-in. No I/O operation is involved.
- `marshal` - Provides methods for marshalling and unmarshalling the protocol in sync flavor.
- `async_marshal` - Provides methods for marshalling and unmarshalling the protocol in async flavor.
- 
The root of the protocol abstraction is the [`Header`](https://docs.rs/asport/latest/asport/enum.Header.html).

## Usage

Run the following command to add this crate as a dependency:

```bash
cargo add asport
```

## License
This crate is licensed under [GNU General Public License v3.0 or later](https://github.com/AkinoKaede/asport/blob/main/LICENSE).

SPDX-License-Identifier: [GPL-3.0-or-later](https://spdx.org/licenses/GPL-3.0-or-later.html)