use crate::error::{Error, Result};

pub const MAX_VARINT: usize = 8;

pub fn encode_varint(buf: &mut Vec<u8>, v: u64) {
    if v < (1 << 6) {
        buf.push(v as u8);
    } else if v < (1 << 14) {
        buf.push(((v >> 8) as u8) | 0x40);
        buf.push(v as u8);
    } else if v < (1 << 30) {
        buf.push(((v >> 24) as u8) | 0x80);
        buf.extend_from_slice(&(v as u32).to_be_bytes()[1..]);
    } else {
        buf.push(((v >> 56) as u8) | 0xc0);
        buf.extend_from_slice(&v.to_be_bytes()[1..]);
    }
}

pub fn encode_varint_len(v: u64) -> usize {
    if v < (1 << 6) {
        1
    } else if v < (1 << 14) {
        2
    } else if v < (1 << 30) {
        4
    } else {
        8
    }
}

pub fn decode_varint(buf: &[u8]) -> Result<(u64, usize)> {
    let &first = buf.first().ok_or(Error::UnexpectedEof)?;
    let tag = first >> 6;
    let len = 1usize << tag;
    if buf.len() < len {
        return Err(Error::UnexpectedEof);
    }
    let mut v: u64 = (first & 0x3f) as u64;
    for &b in &buf[1..len] {
        v = (v << 8) | b as u64;
    }
    Ok((v, len))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        for v in [0u64, 1, 63, 64, 16383, 16384, (1 << 30) - 1, 1 << 30, (1 << 62) - 1] {
            let mut buf = Vec::new();
            encode_varint(&mut buf, v);
            assert_eq!(encode_varint_len(v), buf.len());
            let (decoded, used) = decode_varint(&buf).unwrap();
            assert_eq!(decoded, v);
            assert_eq!(used, buf.len());
        }
    }

    #[test]
    fn boundaries() {
        assert_eq!(encode_varint_len(63), 1);
        assert_eq!(encode_varint_len(64), 2);
        assert_eq!(encode_varint_len((1 << 14) - 1), 2);
        assert_eq!(encode_varint_len(1 << 14), 4);
    }

    #[test]
    fn decode_empty_is_eof() {
        assert!(decode_varint(&[]).is_err());
    }

    #[test]
    fn decode_truncated_two_byte() {
        // тег 0x40 => нужно 2 байта, но пришёл только один
        assert!(decode_varint(&[0x40]).is_err());
    }

    #[test]
    fn decode_truncated_four_byte() {
        // тег 0x80 => нужно 4 байта
        assert!(decode_varint(&[0x80, 0x01, 0x02]).is_err());
    }

    #[test]
    fn decode_truncated_eight_byte() {
        // тег 0xc0 => нужно 8 байт
        assert!(decode_varint(&[0xc0, 0, 0, 0, 0, 0, 0]).is_err());
    }

    #[test]
    fn decode_preserves_value_after_partial_write_never_panics() {
        // однобайтовый varint всегда декодируется
        for v in 0u64..=63 {
            let mut buf = Vec::new();
            encode_varint(&mut buf, v);
            assert_eq!(decode_varint(&buf).unwrap().0, v);
        }
    }
}