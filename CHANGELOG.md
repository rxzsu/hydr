# Changelog

Все заметные изменения проекта будут документированы здесь.
Формат основан на [Keep a Changelog](https://keepachangelog.com/ru/1.1.0/),
версии — [Semantic Versioning](https://semver.org/lang/ru/).

## [Unreleased]

## [0.1.0] - 2026-08-28
### Добавлено
- QUIC и WebSocket транспорты с единым message-слоем.
- Аутентификация challenge-response (`BLAKE3 keyed_hash`) + защита от replay (nonce-cache Bounded FIFO с TTL).
- Обфускация WS (XOR + BLAKE3 MAC + packet-level anti-replay).
- MUX на WS (per-session re-auth), multi-hop релей.
- Brutal-style congestion control (`hydr-cc`) для QUIC.
- SOCKS5 TCP+UDP клиент, UDP-менеджер сервера.
- TLS: self-signed с persist в PEM (`0o600`) и pin по SHA-256 fingerprint.
- Примеры конфигов с предупреждением про `insecure`.

### Безопасность
- `derive_key` через `blake3::derive_key` с доменным разделителем `hydr v1 auth proof`.
- Соль обфускации через `getrandom` (CSPRNG).
- WS outbound переполнение — тихий дроп UDP-датаграмм с метрикой `ws_datagram_dropped`.

### Исправлено
- Nonce-кэш: вытеснение старейшей записи + TTL 10 мин (ранее сброс всего кэша).
- Flow-control WS (кадр `0x0b`), неблокирующая доставка без HOL-blocking.
- Клиентский reconnect с jitter.

### Инфраструктура
- `MSRV = 1.84.0` (`resolver = 3`, `edition 2024`).
- CI: `cargo test` / `clippy -D warnings` / `cargo audit` / `cargo deny`.
- `LICENSE` (MIT), `SECURITY.md`.
