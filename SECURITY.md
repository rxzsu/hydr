# Security Policy

## Поддерживаемые версии
| Версия | Поддерживается |
|--------|---------------|
| 0.1.x  | yes           |

## Сообщение об уязвимости
- Не открывайте публичный issue для уязвимостей.
- Напишите на `security@hydr.invalid` (или создайте приватный security advisory на GitHub).
- Опишите impact, PoC, версию. Ответ — в течение 72 часов.

## Модель угроз
- Пароль никогда не уходит в сеть: `auth_proof = BLAKE3::derive_key("hydr v1 auth proof", password) + keyed_hash(nonce)`.
- Сервер хранит bounded nonce-cache (FIFO 8192 + TTL 10 мин) — повтор того же `client_nonce` отклоняется `ERR_PROTOCOL (0x05)`.
- QUIC шифруется TLS 1.3; WS — опциональная обфускация (XOR + BLAKE3 MAC + replay-window). Для production пин `fingerprint` (SHA-256 DER), не `insecure:true`.
- Обфускация использует `getrandom` для соли и монотонный `seq` + `ReplayFilter` — replay-пакеты дропаются без разрыва, плохой MAC — разрыв.
- Серверные PEM `cert.pem`/`key.pem` пишутся атомарно с `0o600`.

## Рекомендации по развертыванию
- Пароль ≥ 32 байта энтропии (генерируйте `openssl rand -base64 24`), храните в `password_file` или `HYDR_PASSWORD`, файл `0o600`.
- Включите `fingerprint` pinning вместо `insecure`.
- Ограничьте `max_conns`, включите firewall для `quic.bind`/`ws.bind`.
- Регулярно запускайте `cargo audit` / `cargo deny`.
