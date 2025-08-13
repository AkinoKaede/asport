# ASPORT Protocol Specification

## Version

`0x00` _DRAFT_

## Conventions

The key terms "MUST", "SHOULD" and "SHOULD NOT" in this protocol specification are to be interpreted as described
in [RFC2119](https://datatracker.ietf.org/doc/html/rfc2119).

## Overview

ASPORT uses QUIC as its transport layer, which is a multiplexed, secure, and reliable transport protocol.

Any stream or unreliable datagram sent from the client and server side will sent a `Command` header before the payload.
The `Command` header contains the type of the command and the command-specific data.

All fields are in Big Endian unless otherwise noted.

## Command

The Definition of the `Command` header is as follows:

```p4
enum bit<8> CmdType {
    ClientHello = 0,
    ServerHello = 1,
    Connect = 2,
    Packet = 3,
    Dissociate = 4,
    Heartbeat = 5
};

header command_t {
    bit<8> version;
    CmdType cmd_type;
};

header_union command_body {
    client_hello_h client_hello;
    server_hello_h server_hello;
    connect_h connect;
    packet_h packet;
    dissociate_h dissociate;
    heartbeat_h heartbeat;
};
```

`version` is the version of the ASPORT protocol. The current version is `0x00`.

### Address

Before we dive into the details of each command, we need to define the `Address` header.

Address is a header that contains the address family, the address itself, and the port. It's Socks5-like, but
without the domain name and add a none type.

```p4
enum bit<8> AddressFamily {
    Ipv4 = 1,
    Ipv6 = 4,
    None = 255
};

header empty_h { }

header ipv4_h {
    bit<32> addr;
}

header ipv6_h {
    bit<128> addr;
}

header port_h {
    bit<16> port;
}

header_union address_t {
    ipv4_h ipv4;
    ipv6_h ipv6;
    empty_h none;
};

header_union port_t {
    port_h port;
    empty_h none;
};

struct address_h {
    AddressFamily family;
    address_t address;
    port_t port;
};
```

### ClientHello

- Command Type Code: `0x00`
- Transport: Unidirectional Stream
- Direction: Client -> Server

After the QUIC handshake, the client sends a `ClientHello` command to the server. The `ClientHello` command contains
the UUID, the token, the flags, and the expected port range.

The `token` is a 256-bit hash of the user's uuid and password
using [TLS Keying Material Exporter](https://www.rfc-editor.org/rfc/rfc5705) on current TLS session if using TLS as
security layer. The pseudocode as follows:

```pesudo
token =  TLS_ExportKeyingMaterial(uuid, password)
```

If failed to export the TLS keying material (for example, use Noise as security layer), the client SHOULD use BLAKE3-256
to hash the uuid and password, and then convert it to a 256-bit token, and the pseudocode as follows:

```pesudo
function export_keying_material(label, context)
    info = "asport key derivation"
    derived_key = BLAKE3_DeriveKey(info, context)
    mac = BLAKE3_KeyedHash(derived_key, label)
    return mac
end function


token = derive_and_mac(context_data, label_data)
```

The server will verify the token to authenticate the user.

The `Flags` is a bitmask that indicates the features that the client supports. The `Tcp` flag indicates that the client
supports TCP forwarding. The `UdpEnabled` flag indicates that the client supports UDP forwarding. The `UdpModeQuic` flag
indicates that the client wants to use QUIC mode for UDP forwarding.

The expected port range is a header that contains the start and end port of the expected port range.

```p4
struct expected_port_range_t {
    bit<16> start;
    bit<16> end;
}

enum bit<8> Flags {
    Tcp = 1,         // 0b00000001
    UdpEnabled = 2,  // 0b00000010
    UdpModeQuic = 4  // 0b00000100
}

header client_hello_h {
    bit<128> uuid;
    bit<256> token;
    Flags flags;
    expected_port_range_t expected_port_range;
}
```

### ServerHello

- Command Type Code: `0x01`
- Transport: Unidirectional Stream
- Direction: Server -> Client

After the server receives the `ClientHello` command, server SHOULD authenticate the user and bind the port, then send
a `ServerHello` command to the client.

The `ServerHello` command contains the code and the body. The code is the result of the authentication and binding
process.

If authentication is successful and the port is bound, the server MUST send `Success` and the port that is bound.
The port MUST in the expected port range.

If UUID is not found or the token is invalid, the server can send `AuthFailed` and close the connection. For bypass
some probing, the server can also close the connection directly without sending any `ServerHello` command.

If not any port can be bound, the server SHOULD send `BindFailed` and close the connection.

If server not allow any port in the expected port range, the server SHOULD send `PortDenied` and close the connection.

And if the server not allow all the network that the client want to forward, the server SHOULD send `NetworkDenied` and
close the connection.

```p4
enum bit<8> ServerHelloCode {
    Success = 0,
    AuthFailed = 1,
    BindFailed = 2,
    PortDenied = 3,
    NetworkDenied = 4
};

header port_h {
    bit<16> port;
}

header empty_h { }

header_union server_hello_body {
    port_h port;
    empty_h none;
};

header server_hello_h {
    ServerHelloCode code;
    server_hello_body body;
};
```

### Connect

- Command Type Code: `0x02`
- Transport: Bidirectional Stream
- Direction: Server -> Client

When the server receives a TCP connection, the server SHOULD send a `Connect` command to the client on the
bidirectional stream. The `Connect` command contains the address of the source server.

After the client receives the `Connect` command, the client SHOULD open a TCP connection to the target that the
client wants to forward.

The client and server SHOULD forwarding data between two TCP connections and the bidirectional stream.

```p4
header connect_h {
    address_h address;
};
```

### Packet

- Command Type Code: `0x03`
- Transport: Unreliable Datagram / Unreliable Datagram
- Direction: Client -> Server / Server -> Client

ASPORT achieves 0-RTT UDP forwarding by syncing UDP session ID (associate ID) between the client and the server.

Client SHOULD create a UDP session table for each QUIC connection, mapping every associate ID to an associated UDP
socket.

Server SHOULD crate a UDP session table for each QUIC connection, mapping every associate ID to a source address.

The associate ID is a 16-bit unsigned integer generated by the server.

When receiving a UDP packet, the server SHOULD check the source address is already associated with an associate ID.
If not, the server SHOULD allocate an associate ID for the source address and prefix the UDP packet with the `Packet`
command header then sends to the client.

When receiving a `Packet` command, the client SHOULD check whether the associate ID is already associated with a UDP
socket.
If not, the client SHOULD allocate a UDP socket for the associate ID and send the UDP packet to the target that the
client wants to forward and accept UDP packets from any destination at the same time, prefixing them with the `Packet`
command header then sends back to the server. The server should check the associate ID and the target address before
forwarding the UDP packet. If the associate ID is not found or the target address is not the same as the source address,
the server SHOULD drop the packet.

For performance, the client can remove the UDP socket in the session table after a period of inactivity.

`Packet` command can be send through:

- QUIC unreliable datagram (Native Mode).
- QUIC uni-directional stream (QUIC Mode).

In native mode, the size of prefixed UDP packet may large than MTU, so the client SHOULD fragment the UDP packet and
prefix them with the `Packet` command header. In QUIC mode, the packet SHOULD be sent in one piece.

The server MUST send the `Packet` command in the way that the client requested in the `ClientHello` command.

For the fragmented UDP packet, the first fragment SHOULD contain the source address or the target address, and other
fragments SHOULD use the `None` address type.

```p4
header packet_h {
    bit<16> assoc_id;
    bit<16> pkt_id;
    bit<8> frag_total;
    bit<8> frag_id;
    bit<16> size;
    address_h address;
};
```

### Dissociate

- Command Type Code: `0x04`
- Transport: Unidirectional Stream
- Direction: Server -> Client

The server can dissociate a UDP session by sending a `Dissociate` command to the client. The client SHOULD remove the
UDP socket in the session table after receiving the `Dissociate` command.

```p4
header dissociate_h {
    bit<16> assoc_id;
};
```

### Heartbeat

- Command Type Code: `0x05`
- Transport: Unreliable Datagram
- Direction: Client -> Server

Heartbeat is a command that is used to keep the connection alive. The client SHOULD send it using the unreliable
datagram in a interval.
The payload of the `Heartbeat` command is empty.

```p4
header heartbeat_h {
};
```