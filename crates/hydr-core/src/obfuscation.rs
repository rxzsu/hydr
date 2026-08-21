use blake3::Hasher;

use crate::message::TAG_LEN;

pub const SALT_LEN: usize = 8;

pub struct Obfuscator {
    key: Vec<u8>,
    key32: [u8; 32],
}

impl Obfuscator {
    pub fn new(key: &[u8]) -> Self {
        let key32 = *blake3::hash(key).as_bytes();
        Self {
            key: key.to_vec(),
            key32,
        }
    }

    pub fn encrypt(&self, buf: &mut Vec<u8>) {
        let salt: Vec<u8> = (0..SALT_LEN).map(|_| rand_byte()).collect();
        let mut body = buf.clone();
        self.xor_in_place(&mut body, &salt);
        let tag = self.tag(&body);
        let mut out = salt;
        out.extend_from_slice(&body);
        out.extend_from_slice(&tag);
        *buf = out;
    }

    pub fn decrypt(&self, buf: &[u8]) -> Option<Vec<u8>> {
        if buf.len() < SALT_LEN + TAG_LEN {
            return None;
        }
        let (salt, rest) = buf.split_at(SALT_LEN);
        let (body, tag) = rest.split_at(rest.len() - TAG_LEN);
        if self.tag(body) != tag {
            return None;
        }
        let mut out = body.to_vec();
        self.xor_in_place(&mut out[..], salt);
        Some(out)
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
        assert!(ob.decrypt(&[0u8; SALT_LEN + TAG_LEN - 1]).is_none());
    }

    #[test]
    fn encrypted_has_salt_prefix_and_differs() {
        let ob = Obfuscator::new(b"key");
        let payload = b"sensitive".to_vec();
        let mut out = payload.clone();
        ob.encrypt(&mut out);
        assert!(out.len() >= SALT_LEN + TAG_LEN);
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
}