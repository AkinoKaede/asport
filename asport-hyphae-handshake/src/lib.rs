#![allow(
    dead_code,
    unused_assignments,
    clippy::comparison_to_empty,
    clippy::collapsible_else_if,
    clippy::expect_fun_call,
    clippy::get_first,
    clippy::len_without_is_empty,
    clippy::manual_inspect,
    clippy::map_identity,
    clippy::match_like_matches_macro,
    clippy::needless_borrow,
    clippy::needless_return,
    clippy::option_as_ref_deref,
    clippy::possible_missing_else,
    clippy::redundant_pattern_matching,
    clippy::redundant_static_lifetimes,
    clippy::type_complexity,
    clippy::unnecessary_cast,
    clippy::while_let_on_iterator
)]
#![allow(rustdoc::bare_urls)]

pub mod buffer;
#[cfg(test)]
pub(crate) mod builder;
pub mod crypto;
pub mod customization;
pub mod handshake;
pub mod quic;

#[cfg(test)]
mod diagnostics {
    pub mod handshake_harness;
}

#[derive(PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum Error {
    HandshakeFailed,
    BufferSize,
    UnsupportedVersion,
    Internal,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        core::fmt::Debug::fmt(&self, f)
    }
}

impl core::error::Error for Error {}
