use blake3::Hasher;

pub const SALT_LEN: usize = 8;

pub struct Obfuscator {
    key: Vec<u8>,
}

impl Obfuscator {
    pub fn new(key: &[u8]) -> Self {
        Self { key: key.to_vec() }
    }

    pub fn encrypt(&self, buf: &mut Vec<u8>) {
        let salt: Vec<u8> = (0..SALT_LEN).map(|_| rand_byte()).collect();
        let mut out = salt.clone();
        out.extend_from_slice(buf);
        self.xor_in_place(&mut out[SALT_LEN..], &salt);
        *buf = out;
    }

    pub fn decrypt(&self, buf: &[u8]) -> Option<Vec<u8>> {
        if buf.len() < SALT_LEN {
            return None;
        }
        let (salt, payload) = buf.split_at(SALT_LEN);
        let mut out = payload.to_vec();
        self.xor_in_place(&mut out[..], salt);
        Some(out)
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
        assert_ne!(b.decrypt(&payload).unwrap(), b"hello".to_vec());
    }
}