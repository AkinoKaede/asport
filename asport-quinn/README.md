# asport-quinn

A wrapped [quinn](https://github.com/quinn-rs/quinn) to implement ASPORT protocol.

[![Version](https://img.shields.io/crates/v/asport-quinn.svg?style=flat)](https://crates.io/crates/asport-quinn)
[![Documentation](https://img.shields.io/badge/docs-release-brightgreen.svg?style=flat)](https://docs.rs/asport-quinn)
[![License](https://img.shields.io/crates/l/asport-quinn.svg?style=flat)](https://github.com/AkinoKaede/asport/blob/main/LICENSE)

## Overview

This crate provides a wrapper [`Connection`](https://docs.rs/asport-quinn/latest/asport_quinn/struct.Connection.html) around [`quinn::Connection`](https://docs.rs/quinn/latest/quinn/struct.Connection.html).

## Usage

Run the following command to add this crate as a dependency:

```bash
cargo add asport-quinn
```

## License
This crate is licensed under [GNU General Public License v3.0 or later](https://github.com/AkinoKaede/asport/blob/main/LICENSE).

SPDX-License-Identifier: [GPL-3.0-or-later](https://spdx.org/licenses/GPL-3.0-or-later.html)