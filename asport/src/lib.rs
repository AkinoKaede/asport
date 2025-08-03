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

pub use self::protocol::{
    Address, ClientHello, Connect, Dissociate, Flags, Header, Heartbeat, Packet, ServerHello, VERSION,
};
#[cfg(any(feature = "async_marshal", feature = "marshal"))]
pub use self::unmarshal::UnmarshalError;

mod protocol;

#[cfg(feature = "model")]
pub mod model;

#[cfg(any(feature = "async_marshal", feature = "marshal"))]
mod marshal;

#[cfg(any(feature = "async_marshal", feature = "marshal"))]
mod unmarshal;

