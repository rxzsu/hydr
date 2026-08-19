# Hydr

**Hydr** (styled `hydr`) — a TCP & UDP proxy protocol in the spirit of
[Hysteria 2](https://hysteria.network): fast, secure, censorship-resistant.

It runs over two interchangeable transports — **QUIC** and **WebSocket** —
sharing one message layer, with optional XOR obfuscation (WS), multi-hop
chaining, and a brutal-style rate-based congestion control.

## Crates

| Crate           | Purpose                                              |
|-----------------|------------------------------------------------------|
| `hydr-core`     | Wire format: varints, frames, messages, obfuscator   |
| `hydr-transport`| `Tunnel` abstraction: QUIC (quinn) + WS transports   |
| `hydr-server`   | Server: auth, TCP/UDP forwarding, multi-hop, binary  |
| `hydr-client`   | Client: SOCKS5 entry (TCP + UDP), binary             |
| `hydr-cc`       | Brutal-style congestion controller for quinn         |

## Quick start

```sh
cargo build --release

# server
hydr-server -c examples/server.example.yaml

# client
hydr-client -c examples/client.example.yaml
# then: curl --socks5 127.0.0.1:1080 http://example.com
```

See [PROTOCOL.md](PROTOCOL.md) for the wire specification.

## Status

- Protocol draft **v1** implemented; QUIC + WS, TCP + UDP, obfuscation,
  multi-hop, brutal CC, SOCKS5 client, CLI binaries.
- 34 integration/unit tests green; clippy clean.