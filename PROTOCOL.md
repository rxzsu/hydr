# Hydr Protocol Specification

**Hydr** (styled `hydr`) is a TCP & UDP proxy protocol inspired by
[Hysteria 2](https://hysteria.network), designed for speed, security, and
censorship resistance. It runs over two interchangeable transports:
**QUIC** and **WebSocket**, exposing a common message layer on top.

> Status: **draft v1**. Implemented in `crates/hydr-core`.

## Requirements Language

The keywords "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be
interpreted as described in RFC 2119.

## Overview

```
+---------------------------------------------------------------+
| Session layer (multi-hop, client mux)                         |
+---------------------------------------------------------------+
| Message layer (Auth, OpenStream, Datagram, Ping/Pong)         |
+---------------------------------------------------------------+
| Transport (QUIC streams/datagrams OR WebSocket frames)        |
+---------------------------------------------------------------+
| TCP / UDP / TLS                                              |
+---------------------------------------------------------------+
```

The message layer is identical over both transports, so a client speaking QUIC
can talk to a server behind WS and vice versa. Transport selection is purely
a connection detail.

## Wire Format

- All multibyte integers are Big Endian.
- Variable-length integers ("varints") are encoded per QUIC (RFC 9000),
  values limited to 62 bits.

### Address

```
[uint8]  type   (0x01 = IPv4, 0x02 = IPv6, 0x03 = Domain)
[bytes]  addr   (4 / 16 / varint-length-prefixed)
[uint16] port
```

### Authentication

The first message on every tunnel MUST be an `AuthRequest` on the control
channel (stream id `0`). The server replies with an `AuthResponse`.

The password is **never sent in clear text**. Instead the client generates a
random `client_nonce` and proves knowledge of the password by sending
`auth_proof = keyed_hash(password, client_nonce)` (BLAKE3 keyed hash). The
server recomputes the value from its own password and the received nonce and
compares it in constant time. Because `auth_proof` is bound to the nonce, a
captured handshake cannot be replayed: the server remembers recently seen
nonces and rejects duplicates.

```
AuthRequest:
  [varint] version        (0x01)
  [uint8]  auth_method    (0x01 = password-proof)
  [varint] client_nonce_len
  [bytes]  client_nonce   (>= 8 random bytes, replay protection)
  [varint] auth_proof_len
  [bytes]  auth_proof     (keyed_hash(password, client_nonce))
  [varint] cc_rx          (client max receive rate, bytes/s; 0 = unknown)
  [uint8]  features       (bit 0 = UDP)
  [varint] padding_len
  [bytes]  padding

AuthResponse:
  [uint8]  status          (0x00 = OK, 0x01 = Error)
  [uint8]  error_code      (machine-readable; 0 when OK)
  [varint] msg_len
  [bytes]  msg
  [varint] server_cc_rx    (server max receive rate; 0 = unlimited)
  [uint8]  server_features
  [varint] padding_len
  [bytes]  padding
```

`error_code` values: `0x00` none, `0x01` bad credentials, `0x02` rate
limited, `0x03` connect failed, `0x04` unsupported (e.g. protocol version),
`0x05` protocol violation (e.g. replay), `0x06` internal.

If authentication fails the server MUST close the tunnel.

### TCP

Each TCP proxy connection is a **stream**. The client opens the stream and
sends an `OpenStream` message; the server answers with `OpenStreamAck`. After
an OK acknowledgement the stream carries raw bytes in both directions until
either side closes.

```
OpenStream:
  [address] target

OpenStreamAck:
  [uint8]  status   (0x00 = OK, 0x01 = Error)
  [uint8]  error_code  (machine-readable; matches AuthResponse codes)
  [varint] msg_len
  [bytes]  msg
```

### UDP

UDP packets MUST be encapsulated in `Datagram` messages. They travel over
QUIC unreliable datagrams (RFC 9221) on the QUIC transport, or as Datagram
frames on WS.

```
Datagram:
  [uint32] session_id
  [uint16] packet_id
  [uint8]  frag_id
  [uint8]  frag_count
  [address] target
  [bytes]  payload
```

The client MUST use a unique `session_id` per UDP session. The server assigns
a local UDP socket per session id.

#### Fragmentation

Any UDP payload exceeding the transport datagram limit MUST be fragmented:
all fragments carry the same `packet_id`, `frag_id` indexes into
`frag_count`. A fragmented packet is discarded if any fragment is lost.
Unfragmented packets set `frag_count = 1`.

## Transports

### QUIC

- Transport: QUIC (RFC 9000) with Unreliable Datagram extension (RFC 9221).
- TLS 1.3 encryption is provided by QUIC itself.
- Control + authentication: bidirectional stream 0.
- TCP: one bidirectional QUIC stream per proxy connection.
- UDP: QUIC datagrams carrying `Datagram` messages.

### WebSocket

- Transport: RFC 6455 over TLS (or plain TCP, configurable).
- Because WS is a single byte pipe, hydr adds a multiplexing frame header:

```
Frame:
  [varint] stream_id
  [uint8]  type
  [varint] body_len
  [bytes]  body

types:
  0x01 OpenStream       body = OpenStream
  0x02 OpenStreamAck    body = OpenStreamAck
  0x03 StreamData       raw bytes
  0x04 StreamClose      EOF marker
  0x05 Datagram         body = Datagram
  0x06 Ping
  0x07 Pong
  0x08 AuthRequest      body = AuthRequest
  0x09 AuthResponse     body = AuthResponse
  0x0a SessionClose
```

Stream id `0` is the control channel. `StreamData`/`StreamClose` frames are
dispatched to the stream matching `stream_id`.

## Session Multiplexing (MUX)

> **Status (draft v1.1):** not implemented. The `FEATURE_MUX` flag was removed
> from the wire format; currently each transport connection carries a single
> authenticated tunnel. Logical multiplexing over QUIC is already provided
> natively by QUIC streams, and over WS by the frame `stream_id`. True
> per-session re-authentication (each logical session performing its own
> `AuthRequest`/`AuthResponse` exchange) remains future work and is the
> foundation for multi-hop chains with distinct credentials per hop.

## Multi-hop / Chaining

A hydr server MAY be configured with a `next_hop`. In that case every tunnel
is relayed to the next hop: the server behaves as a hydr client towards the
next hop and forwards streams/datagrams between the two tunnels. This allows
traffic to traverse multiple nodes.

## Congestion Control

Like Hysteria, hydr supports rate-based transmission. `cc_rx` values are
exchanged during authentication:

- client `cc_rx = 0`  → server picks its own congestion control.
- server `cc_rx = 0`  → server declares unlimited receive rate; the client may
  transmit aggressively.
- otherwise the receiver advertises its receive ceiling and the sender paces
  to it.

When `cc_rx > 0`, the QUIC transport uses `hydr-cc`'s brutal-style controller:
the congestion window is always `rate / 8 × RTT` and is never reduced on
packet loss (in contrast to NewReno/CUBIC). Each side applies its own
configured `cc_rx` to its sending direction. The WS transport has no
congestion control (TCP governs the flow).

## Obfuscation

An optional XOR obfuscation layer ("Salamander-style") MAY wrap every
transport datagram/byte:

```
[8 bytes]  salt
[bytes]    ciphertext  (ciphertext[i] ^= BLAKE3(key || salt)[i % 32])
[16 bytes] tag         (keyed_hash(key32, ciphertext), first 16 bytes)
```

Without the pre-shared obfuscation key the stream is indistinguishable from
random bytes. The trailing `tag` is a keyed BLAKE3 MAC over the ciphertext, so
a peer holding the wrong key (or a tampered message) fails verification and the
frame is discarded. This gives the obfuscation layer integrity and
authentication on top of its scrambling, protecting datagrams carried over WS
(which otherwise have no per-message authentication of their own).

The layer is configured per-endpoint with a pre-shared key. In the WS
transport it is applied per WebSocket binary message: the frame bytes are
obfuscated before send and de-obfuscated on receive (one random salt per
message, stateless). The QUIC transport uses QUIC's built-in encryption; the
obfuscation layer is therefore applied to WS only (packet-level scrambling of
QUIC would require a custom packet API, which `quinn` does not expose).
Both peers MUST use the same key and enable/disable the layer in sync;
a key mismatch makes the peer's frames undecodable and the connection fails.
