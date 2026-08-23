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
# note the printed QUIC certificate fingerprint (sha256)

# client
hydr-client -c examples/client.example.yaml
# then: curl --socks5 127.0.0.1:1080 http://example.com
```

See [PROTOCOL.md](PROTOCOL.md) for the wire specification.

## Security notes

- Auth never sends the password: it proves knowledge via a keyed hash over a
  random nonce, and the server rejects nonce replays.
- Servers use self-signed certificates. The server prints its certificate's
  SHA-256 fingerprint on startup; clients pin it (`fingerprint` in the
  transport config) for MITM protection without a public CA. Persist the
  server certificate to PEM files (`quic.cert` / `quic.key`) so the
  fingerprint survives restarts.

## Status

- Protocol draft **v1.1** implemented; QUIC + WS, TCP + UDP, obfuscation,
  multi-hop, brutal CC, SOCKS5 client (with tunnel-reconnect), per-stream WS
  flow control, CLI binaries.
- 110 integration/unit tests green; clippy clean.