# AGENTS.md — Hydr

Справочник для ИИ-агентов, работающих с этим репозиторием. Общайся с пользователем
на русском, технические идентификаторы — на английском.

## Что это

**Hydr** — TCP/UDP proxy-протокол в духе Hysteria 2, написанный на Rust.
Работает поверх двух взаимозаменяемых транспортов — **QUIC** (через `quinn`)
и **WebSocket** — с единым message-слоем поверх. Есть опциональная XOR-обфускация
(WS), многоскачковая маршрутизация (multi-hop) и brutal-подобный rate-based
congestion control. Клиент — SOCKS5-вход (TCP + UDP), сервер — форвардинг и
цепочки next-hop.

Статус: **draft v1.1**. Сборка `cargo build --release` даёт бинарники
`hydr-server` и `hydr-client`.

## Структура (workspace, resolver = 3, edition 2024)

| Крейт | Назначение |
|-------|-----------|
| `hydr-core` | Wire-формат: varint, address, frame, message, obfuscation. Чистый, без I/O. |
| `hydr-transport` | `Tunnel`/`TunnelHandle`: QUIC (`quic.rs`) + WS (`ws.rs`) транспорты, TLS (`tls.rs`). |
| `hydr-server` | Сервер: auth, TCP/UDP форвардинг, multi-hop, анти-DoS, graceful shutdown. Бинарник + CLI. |
| `hydr-client` | SOCKS5-клиент (QUIC/WS транспорт), UDP-relay, реконнект. Бинарник + CLI. |
| `hydr-cc` | Brutal-style congestion controller для `quinn` (окно = `rate/8 × RTT`, игнор потерь). |

Зависимости: `blake3` (хеши/MAC), `getrandom` (nonce), `quinn` 0.11,
`tokio-tungstenite`, `tokio`, `rustls`, `rcgen` (self-signed), `rand` (в server).
Сборка требует установленного TLS-провайдера: тесты/бинарники вызывают
`hydr_transport::tls::install_default_provider()`.

## Команды

```sh
cargo build --release                 # бинарники server/client
cargo test                            # все тесты (unit + integration)
cargo test -p hydr-core               # только юнит-тесты wire-формата
cargo clippy --workspace --all-targets # проект претендует на чистый clippy
```

Интеграционные тесты асинхронные, помечены
`#[tokio::test(flavor = "multi_thread", worker_threads = 4)]` и поднимают
реальные QUIC/WS-эндпоинты на `127.0.0.1:0`. Не делай их однопоточными — QUIC
handshake этого не любит.

## Архитектура протокола

```
Сессионный слой (multi-hop, реконнект клиента)
  └─ Message layer: AuthRequest/Response, OpenStream/Ack, Datagram, Ping/Pong
       └─ Transport: QUIC streams/datagrams  ИЛИ  WebSocket frames
            └─ TCP / UDP / TLS
```

- **Message layer** идентичен на обоих транспортах (`hydr-core::message`).
- **QUIC**: control = stream 0; TCP = один bidirectional QUIC-стрим на соединение;
  UDP = QUIC unreliable datagrams (RFC 9221). Шифрует сам QUIC (TLS 1.3).
- **WebSocket**: один байтовый поток → мультиплексирующий `Frame`
  (`stream_id`, `type`, `body_len`, `body`). Обфускация (XOR + MAC) применяется
  на WS, не на QUIC.

### Аутентификация (важно при правках)
`AuthRequest` НЕ шлёт пароль. Клиент генерит `client_nonce` (16 байт, CSPRNG)
и шлёт `auth_proof = keyed_hash(password, nonce)` (BLAKE3 keyed hash). Сервер
пересчитывает и сравнивает constant-time (`ct_eq`). Сервер хранит bounded-кэш
использованных nonce → повторный коннект с тем же nonce отклоняется
(`ERR_PROTOCOL`). Смена формата `AuthRequest` ломает все хендшейки — обновляй
и клиента, и сервер, и тесты синхронно.

### Коды ошибок
`AuthResponse` и `OpenStreamAck` несут `error_code` (машиночитаемый):
`0` none, `1` bad credentials, `2` rate limited, `3` connect failed,
`4` unsupported, `5` protocol violation (replay), `6` internal.

### Обфускация
`Obfuscator` (только WS): `salt(8) || ciphertext(XOR) || tag(16, keyed BLAKE3)`.
`decrypt` проверяет тег и возвращает `None` при несовпадении. Ключ pre-shared.
Меняешь формат — обнови тесты `obfuscation.rs`.

### Congestion control
`hydr-cc::transport_config(rate_bps)`: при `rate>0` подключается brutal-контроллер
(окно = `rate/8 × RTT`, не режется при потерях). WS этим не управляется (им
правит TCP).

### Multi-hop / MUX
`next_hop` в `ServerConfig` релеит туннель на следующий узел (QUIC или WS).
**MUX не реализован**: флаг `FEATURE_MUX` удалён из wire-формата; логический
mux поверх QUIC есть нативно (стримы), поверх WS — `stream_id` фреймов, но
per-session re-auth пока future work.

## Конвенции кода
- Сообщения кодируются `encode(&mut Vec<u8>)` / декодируются `decode(&[u8]) -> Result<(_, usize)>`
  (возвращают потребленную длину). Декодеры обязаны корректно отдавать `UnexpectedEof`
  на обрезанных буферах — покрыто юнит-тестами в `hydr-core`.
- Ошибки — `hydr_core::Error` (`Io`, `UnexpectedEof`, `InvalidData`, `Message`,
  `AuthFailed`, `StreamClosed`, `Unsupported`). В транспорте преобразуются в `io::Error`
  через `quic::to_io_error`.
- Тесты wire-формата — в `#[cfg(test)] mod tests` рядом с кодом. Интеграционные —
  в `tests/` каждого крейта.
- Не добавляй комментарии без просьбы. Старайся не ломать существующие тесты:
  любое изменение wire-формата требует правки `PROTOCOL.md` и соответствующих тестов.

## Частые подводные камни
- QUIC-датаграммы ограничены MTU пути (~1200 байт); тесты на «большие» датаграммы
  для QUIC используют ≤1024 байт, для WS — больше.
- `getrandom` нужен в рантайме (`AuthRequest::new_password` генерит nonce) — в
  тестовой среде доступен, но убедись, что бинарник собирается на целевой платформе.
- `PROTOCOL.md` — источник истины по wire-формату; держи его в синхроне с кодом.
- Один pre-existing clippy-варнинг (`Err`-variant very large в `ws.rs`) не из наших
  правок; не считай его регрессией.
