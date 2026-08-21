use blake3::Hasher;
use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use crate::message::TAG_LEN;

pub const SALT_LEN: usize = 8;

/// Исход расшифровки кадра: успех, replay или невалидный (мусор/плохой MAC).
pub enum DecryptOutcome {
    Ok(Vec<u8>),
    Replay,
    Invalid,
}

/// Скользящее окно anti-replay для последовательностей пакетов.
///
/// Принимает строго возрастающие (в пределах окна) seq; повтор или слишком
/// старый seq отвергаются. `observe` потокобезопасна.
pub struct ReplayFilter {
    inner: Mutex<FilterInner>,
}

struct FilterInner {
    last: u64,
    floor: u64,
    seen: HashSet<u64>,
    window: u64,
}

impl ReplayFilter {
    pub fn new(window: u64) -> Self {
        Self {
            inner: Mutex::new(FilterInner {
                last: 0,
                floor: 0,
                seen: HashSet::new(),
                window,
            }),
        }
    }

    /// Возвращает `true`, если `seq` свежий (принять), `false` при replay/устарело.
    pub fn observe(&self, seq: u64) -> bool {
        let mut g = self.inner.lock().unwrap();
        if seq < g.floor {
            return false;
        }
        if g.seen.contains(&seq) {
            return false;
        }
        g.seen.insert(seq);
        if seq > g.last {
            g.last = seq;
            g.floor = g.last.saturating_sub(g.window);
        }
        if g.seen.len() as u64 > g.window * 2 {
            let min = g.floor;
            g.seen.retain(|x| *x >= min);
        }
        true
    }
}

pub struct Obfuscator {
    key: Vec<u8>,
    key32: [u8; 32],
    send_seq: AtomicU64,
    recv: Mutex<ReplayFilter>,
}

impl Obfuscator {
    pub fn new(key: &[u8]) -> Self {
        let key32 = *blake3::hash(key).as_bytes();
        Self {
            key: key.to_vec(),
            key32,
            send_seq: AtomicU64::new(0),
            recv: Mutex::new(ReplayFilter::new(1 << 16)),
        }
    }

    /// Шифрует `buf` на месте: `salt || xor(seq||payload) || tag`.
    /// `seq` — монотонный счётчик пакетов (встроен в открытый текст под MAC),
    /// что даёт защиту от replay на уровне пакета.
    pub fn encrypt(&self, buf: &mut Vec<u8>) {
        let seq = self.send_seq.fetch_add(1, Ordering::Relaxed);
        let mut plaintext = seq.to_be_bytes().to_vec();
        plaintext.extend_from_slice(buf);
        let salt: Vec<u8> = (0..SALT_LEN).map(|_| rand_byte()).collect();
        let mut body = plaintext;
        self.xor_in_place(&mut body, &salt);
        let tag = self.tag(&body);
        let mut out = salt;
        out.extend_from_slice(&body);
        out.extend_from_slice(&tag);
        *buf = out;
    }

    /// Расшифровывает; `None` при плохом теге, обрезке ИЛИ replay-пакете.
    pub fn decrypt(&self, buf: &[u8]) -> Option<Vec<u8>> {
        match self.decrypt_outcome(buf) {
            DecryptOutcome::Ok(v) => Some(v),
            _ => None,
        }
    }

    /// Детальный результат расшифровки, различающий replay и невалидный кадр.
    /// - `Ok` — успешно;
    /// - `Replay` — корректный MAC, но уже виденный seq (тихо дропаем);
    /// - `Invalid` — плохой MAC / обрезка / мусор (соединение стоит разорвать).
    pub fn decrypt_outcome(&self, buf: &[u8]) -> DecryptOutcome {
        if buf.len() < SALT_LEN + TAG_LEN + 8 {
            return DecryptOutcome::Invalid;
        }
        let (salt, rest) = buf.split_at(SALT_LEN);
        let (body, tag) = rest.split_at(rest.len() - TAG_LEN);
        if self.tag(body) != tag {
            return DecryptOutcome::Invalid;
        }
        let mut plain = body.to_vec();
        self.xor_in_place(&mut plain, salt);
        let (seq_bytes, payload) = plain.split_at(8);
        let seq = match seq_bytes.try_into() {
            Ok(b) => u64::from_be_bytes(b),
            Err(_) => return DecryptOutcome::Invalid,
        };
        if !self.recv.lock().unwrap().observe(seq) {
            return DecryptOutcome::Replay;
        }
        DecryptOutcome::Ok(payload.to_vec())
    }

    fn tag(&self, body: &[u8]) -> Vec<u8> {
        blake3::keyed_hash(&self.key32, body).as_bytes()[..TAG_LEN].to_vec()
    }

    fn xor_in_place(&self, buf: &mut [u8], salt: &[u8]) {
        let mut hasher = Hasher::new();
        hasher.update(&self.key);
        hasher.update(salt);
        let hash = hasher.finalize();
        let key_stream = hash.as_bytes();
        for (i, b) in buf.iter_mut().enumerate() {
            *b ^= key_stream[i % key_stream.len()];
        }
    }
}

fn rand_byte() -> u8 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    ((t ^ (t >> 16)) as u8) ^ (t >> 8) as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let ob = Obfuscator::new(b"super-secret-key");
        let mut payload = vec![0u8; 128];
        for (i, b) in payload.iter_mut().enumerate() {
            *b = i as u8;
        }
        ob.encrypt(&mut payload);
        assert_ne!(payload[..], vec![0u8; 128][..]);
        let dec = ob.decrypt(&payload).unwrap();
        assert_eq!(dec, (0..128u8).collect::<Vec<_>>());
    }

    #[test]
    fn wrong_key_fails() {
        let a = Obfuscator::new(b"key-a");
        let b = Obfuscator::new(b"key-b");
        let mut payload = b"hello".to_vec();
        a.encrypt(&mut payload);
        // неверный ключ => несовпадение тега => None
        assert!(b.decrypt(&payload).is_none());
    }

    #[test]
    fn tampered_ciphertext_rejected() {
        let ob = Obfuscator::new(b"key");
        let mut payload = b"trusted-data".to_vec();
        ob.encrypt(&mut payload);
        // подменим один байт тела — тег не сойдётся
        let idx = SALT_LEN;
        payload[idx] ^= 0xFF;
        assert!(ob.decrypt(&payload).is_none(), "подделка должна отвергаться");
    }

    #[test]
    fn decrypt_too_short_returns_none() {
        let ob = Obfuscator::new(b"k");
        assert!(ob.decrypt(&[]).is_none());
        assert!(ob.decrypt(&[1, 2, 3]).is_none());
        assert!(ob.decrypt(&[0u8; 7]).is_none());
        assert!(ob.decrypt(&[0u8; SALT_LEN + TAG_LEN + 7]).is_none());
    }

    #[test]
    fn encrypted_has_salt_prefix_and_differs() {
        let ob = Obfuscator::new(b"key");
        let payload = b"sensitive".to_vec();
        let mut out = payload.clone();
        ob.encrypt(&mut out);
        assert!(out.len() >= SALT_LEN + TAG_LEN + 8);
        // соль предшествует телу, само тело скрыто
        assert_ne!(&out[SALT_LEN..out.len() - TAG_LEN], &payload[..]);
        assert_ne!(out, payload);
    }

    #[test]
    fn roundtrip_empty_and_tiny() {
        let ob = Obfuscator::new(b"key");
        for len in [0usize, 1, 31, 32, 33, 1000] {
            let original: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let mut enc = original.clone();
            ob.encrypt(&mut enc);
            let dec = ob.decrypt(&enc).unwrap();
            assert_eq!(dec, original, "roundtrip failed for len {len}");
        }
    }

    #[test]
    fn same_key_different_salts_still_decrypt() {
        // каждый encrypt использует случайную соль, но decrypt её учитывает
        let ob = Obfuscator::new(b"shared");
        let mut a = vec![1u8, 2, 3, 4];
        let mut b = vec![1u8, 2, 3, 4];
        ob.encrypt(&mut a);
        ob.encrypt(&mut b);
        assert_ne!(a, b, "разные соли должны давать разный шифр-текст");
        assert_eq!(ob.decrypt(&a).unwrap(), ob.decrypt(&b).unwrap());
    }

    #[test]
    fn replayed_packet_rejected() {
        let ob = Obfuscator::new(b"k");
        let mut p1 = b"hello".to_vec();
        ob.encrypt(&mut p1); // seq 0
        let mut p2 = b"hello".to_vec();
        ob.encrypt(&mut p2); // seq 1
        assert_eq!(ob.decrypt(&p1).unwrap(), b"hello");
        assert_eq!(ob.decrypt(&p2).unwrap(), b"hello");
        // повторная расшифровка p1 (тот же seq 0) => replay => None
        assert!(ob.decrypt(&p1).is_none(), "replay должен отвергаться");
    }

    #[test]
    fn replay_filter_rejects_duplicates() {
        let f = ReplayFilter::new(1024);
        assert!(f.observe(0));
        assert!(f.observe(1));
        assert!(!f.observe(0), "дубликат 0");
        assert!(!f.observe(1), "дубликат 1");
        assert!(f.observe(2));
        // скачок вперёд принимается
        assert!(f.observe(5000));
        // очень старый за пределами окна отвергается (floor = 5000-1024)
        assert!(!f.observe(10));
    }
}
