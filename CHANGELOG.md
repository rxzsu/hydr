# Changelog

Все заметные изменения проекта будут документированы здесь.
Формат основан на [Keep a Changelog](https://keepachangelog.com/ru/1.1.0/),
версии — [Semantic Versioning](https://semver.org/lang/ru/).

## [Unreleased]
### Добавлено
- SOCKS5 user/pass аутентификация (RFC 1929): `socks5_username`/`socks5_password`
  в конфиге клиента (пароль — через `HYDR_SOCKS5_PASSWORD`); warn при бинде
  на не-loopback без auth.
- Prometheus `/metrics` на сервере (`metrics_bind`, например `127.0.0.1:9090`):
  auth по кодам, replay vs bad-MAC, стримы/датаграммы, UDP-сессии, дропы WS,
  ожидания flow-control, окно CC. Без внешних зависимостей.
- Hot-reload QUIC-сертификата без рестарта: SIGHUP (unix) + опрос mtime PEM
  (все ОС); новый fingerprint логируется, живые соединения не рвутся.
- UDP caps: `max_udp_sessions` (дефолт 4096) + `max_udp_sessions_per_ip`
  (дефолт 64); превышение → `[code 0x02]`.

### Безопасность
- UDP-сессии ключеваны `(owner_ip, session_id)`: чужой клиент больше не может
  перехватить/вытеснить чужой сокет подбором `session_id`.
- Brutal-окно зажато в `[2.4 КБ, 64 МБ]`: 10 Гбит/с × 1 с больше не даёт
  окно 1.25 ГБ, убивающее shared-линк.
- CI: `cargo audit` / `cargo deny` — блокирующие; еженедельный strict-аудит
  по расписанию ловит новые CVE в `Cargo.lock` без коммитов.

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
