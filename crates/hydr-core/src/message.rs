use crate::address::Address;
use crate::error::{Error, Result};
use crate::varint::encode_varint;
use std::collections::VecDeque;

pub const PROTOCOL_VERSION: u64 = 0x01;
pub const STATUS_OK: u8 = 0x00;
pub const STATUS_ERR: u8 = 0x01;

pub const FEATURE_UDP: u8 = 0x01;

/// Машиночитаемые коды ошибок (в дополнение к человекочитаемому `message`).
pub const ERR_NONE: u8 = 0x00;
pub const ERR_BAD_CREDENTIALS: u8 = 0x01;
pub const ERR_RATE_LIMITED: u8 = 0x02;
pub const ERR_CONNECT_FAILED: u8 = 0x03;
pub const ERR_UNSUPPORTED: u8 = 0x04;
pub const ERR_PROTOCOL: u8 = 0x05;
pub const ERR_INTERNAL: u8 = 0x06;

/// Длина случайного nonce клиента в `AuthRequest`.
pub const NONCE_LEN: usize = 16;
/// Длина тега целостности в обфускаторе.
pub const TAG_LEN: usize = 16;

/// Производит 32-байтный ключ из пароля (для keyed-hash доказательства).
fn derive_key(password: &[u8]) -> [u8; 32] {
    *blake3::hash(password).as_bytes()
}

/// Доказательство владения паролем: keyed_hash(password, nonce).
/// Сырой пароль в канал не уходит; nonce делает доказательство уникальным.
pub fn compute_auth_proof(password: &[u8], nonce: &[u8]) -> Vec<u8> {
    blake3::keyed_hash(&derive_key(password), nonce).as_bytes().to_vec()
}

/// Константно-по-времени сравнение (защита от timing-атак на доказательство).
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

pub fn random_padding(rng: &mut impl FnMut() -> u8, len: usize) -> Vec<u8> {
    (0..len).map(|_| rng()).collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthRequest {
    pub version: u64,
    pub auth_method: u8,
    pub client_nonce: Vec<u8>,
    pub auth_proof: Vec<u8>,
    pub cc_rx: u64,
    pub features: u8,
    pub padding: Vec<u8>,
}

impl AuthRequest {
    pub const AUTH_PASSWORD: u8 = 0x01;

    /// Строит запрос с доказательством владения паролем.
    /// `client_nonce` генерируется случайно (защита от replay и утечки пароля).
    pub fn new_password(password: &[u8], cc_rx: u64, features: u8) -> Self {
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::getrandom(&mut nonce).expect("CSPRNG unavailable");
        let proof = compute_auth_proof(password, &nonce);
        Self {
            version: PROTOCOL_VERSION,
            auth_method: Self::AUTH_PASSWORD,
            client_nonce: nonce.to_vec(),
            auth_proof: proof,
            cc_rx,
            features,
            padding: Vec::new(),
        }
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        encode_varint(buf, self.version);
        buf.push(self.auth_method);
        encode_varint(buf, self.client_nonce.len() as u64);
        buf.extend_from_slice(&self.client_nonce);
        encode_varint(buf, self.auth_proof.len() as u64);
        buf.extend_from_slice(&self.auth_proof);
        encode_varint(buf, self.cc_rx);
        buf.push(self.features);
        encode_varint(buf, self.padding.len() as u64);
        buf.extend_from_slice(&self.padding);
    }

    pub fn decode(buf: &[u8]) -> Result<(AuthRequest, usize)> {
        let mut rd = Reader::new(buf);
        let version = rd.varint()?;
        let auth_method = rd.u8()?;
        let client_nonce = rd.bytes()?;
        let auth_proof = rd.bytes()?;
        let cc_rx = rd.varint()?;
        let features = rd.u8()?;
        let padding = rd.bytes()?;
        Ok((
            AuthRequest {
                version,
                auth_method,
                client_nonce,
                auth_proof,
                cc_rx,
                features,
                padding,
            },
            rd.pos,
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthResponse {
    pub status: u8,
    pub error_code: u8,
    pub message: Vec<u8>,
    pub server_cc_rx: u64,
    pub server_features: u8,
    pub padding: Vec<u8>,
}

impl AuthResponse {
    pub fn ok(server_cc_rx: u64, server_features: u8) -> Self {
        Self {
            status: STATUS_OK,
            error_code: ERR_NONE,
            message: Vec::new(),
            server_cc_rx,
            server_features,
            padding: Vec::new(),
        }
    }

    pub fn error(msg: &str) -> Self {
        Self::error_with_code(ERR_BAD_CREDENTIALS, msg)
    }

    pub fn error_with_code(error_code: u8, msg: &str) -> Self {
        Self {
            status: STATUS_ERR,
            error_code,
            message: msg.as_bytes().to_vec(),
            server_cc_rx: 0,
            server_features: 0,
            padding: Vec::new(),
        }
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.push(self.status);
        buf.push(self.error_code);
        encode_varint(buf, self.message.len() as u64);
        buf.extend_from_slice(&self.message);
        encode_varint(buf, self.server_cc_rx);
        buf.push(self.server_features);
        encode_varint(buf, self.padding.len() as u64);
        buf.extend_from_slice(&self.padding);
    }

    pub fn decode(buf: &[u8]) -> Result<(AuthResponse, usize)> {
        let mut rd = Reader::new(buf);
        let status = rd.u8()?;
        let error_code = rd.u8()?;
        let message = rd.bytes()?;
        let server_cc_rx = rd.varint()?;
        let server_features = rd.u8()?;
        let padding = rd.bytes()?;
        Ok((
            AuthResponse {
                status,
                error_code,
                message,
                server_cc_rx,
                server_features,
                padding,
            },
            rd.pos,
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenStream {
    pub address: Address,
}

impl OpenStream {
    pub fn encode(&self, buf: &mut Vec<u8>) {
        self.address.encode(buf);
    }

    pub fn decode(buf: &[u8]) -> Result<(OpenStream, usize)> {
        let (address, used) = Address::decode(buf)?;
        Ok((OpenStream { address }, used))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenStreamAck {
    pub status: u8,
    pub error_code: u8,
    pub message: Vec<u8>,
}

impl OpenStreamAck {
    pub fn ok() -> Self {
        Self {
            status: STATUS_OK,
            error_code: ERR_NONE,
            message: Vec::new(),
        }
    }

    pub fn error_with_code(error_code: u8, msg: &str) -> Self {
        Self {
            status: STATUS_ERR,
            error_code,
            message: msg.as_bytes().to_vec(),
        }
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.push(self.status);
        buf.push(self.error_code);
        encode_varint(buf, self.message.len() as u64);
        buf.extend_from_slice(&self.message);
    }

    pub fn decode(buf: &[u8]) -> Result<(OpenStreamAck, usize)> {
        let mut rd = Reader::new(buf);
        let status = rd.u8()?;
        let error_code = rd.u8()?;
        let message = rd.bytes()?;
        Ok((
            OpenStreamAck {
                status,
                error_code,
                message,
            },
            rd.pos,
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Datagram {
    pub session_id: u32,
    pub packet_id: u16,
    pub frag_id: u8,
    pub frag_count: u8,
    pub address: Address,
    pub payload: Vec<u8>,
}

impl Datagram {
    pub fn new(
        session_id: u32,
        address: Address,
        payload: Vec<u8>,
    ) -> Self {
        Self {
            session_id,
            packet_id: 0,
            frag_id: 0,
            frag_count: 1,
            address,
            payload,
        }
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.session_id.to_be_bytes());
        buf.extend_from_slice(&self.packet_id.to_be_bytes());
        buf.push(self.frag_id);
        buf.push(self.frag_count);
        self.address.encode(buf);
        buf.extend_from_slice(&self.payload);
    }

    pub fn decode(buf: &[u8]) -> Result<(Datagram, usize)> {
        if buf.len() < 8 {
            return Err(Error::UnexpectedEof);
        }
        let session_id = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let packet_id = u16::from_be_bytes([buf[4], buf[5]]);
        let frag_id = buf[6];
        let frag_count = buf[7];
        let (address, used) = Address::decode(&buf[8..])?;
        let payload = buf[8 + used..].to_vec();
        Ok((
            Datagram {
                session_id,
                packet_id,
                frag_id,
                frag_count,
                address,
                payload,
            },
            buf.len(),
        ))
    }
}

pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn u8(&mut self) -> Result<u8> {
        let b = *self.buf.get(self.pos).ok_or(Error::UnexpectedEof)?;
        self.pos += 1;
        Ok(b)
    }

    pub fn varint(&mut self) -> Result<u64> {
        let (v, used) = crate::varint::decode_varint(&self.buf[self.pos..])?;
        self.pos += used;
        Ok(v)
    }

    pub fn bytes(&mut self) -> Result<Vec<u8>> {
        let len = self.varint()? as usize;
        if self.buf.len() < self.pos + len {
            return Err(Error::UnexpectedEof);
        }
        let out = self.buf[self.pos..self.pos + len].to_vec();
        self.pos += len;
        Ok(out)
    }

    pub fn remaining(&self) -> &'a [u8] {
        &self.buf[self.pos..]
    }
}

pub type FrameQueue = VecDeque<Vec<u8>>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_roundtrip() {
        let a = AuthRequest::new_password(b"secret", 100_000, FEATURE_UDP);
        let mut buf = Vec::new();
        a.encode(&mut buf);
        let (b, used) = AuthRequest::decode(&buf).unwrap();
        assert_eq!(a, b);
        assert_eq!(used, buf.len());
    }

    #[test]
    fn auth_resp_roundtrip() {
        let a = AuthResponse::ok(0, FEATURE_UDP);
        let mut buf = Vec::new();
        a.encode(&mut buf);
        let (b, used) = AuthResponse::decode(&buf).unwrap();
        assert_eq!(a, b);
        assert_eq!(used, buf.len());
    }

    #[test]
    fn open_stream_roundtrip() {
        let a = OpenStream {
            address: Address::Domain("google.com".into(), 443),
        };
        let mut buf = Vec::new();
        a.encode(&mut buf);
        let (b, used) = OpenStream::decode(&buf).unwrap();
        assert_eq!(a, b);
        assert_eq!(used, buf.len());
    }

    #[test]
    fn datagram_roundtrip() {
        let a = Datagram::new(7, Address::Ip("8.8.8.8".parse().unwrap(), 53), vec![1, 2, 3]);
        let mut buf = Vec::new();
        a.encode(&mut buf);
        let (b, used) = Datagram::decode(&buf).unwrap();
        assert_eq!(a, b);
        assert_eq!(used, buf.len());
    }

    #[test]
    fn datagram_with_fragments_roundtrip() {
        let mut a = Datagram::new(9, Address::Domain("x.example".into(), 1234), vec![4, 5, 6]);
        a.packet_id = 42;
        a.frag_id = 1;
        a.frag_count = 3;
        assert_eq!(a.frag_count, 3);
        let mut buf = Vec::new();
        a.encode(&mut buf);
        let (b, used) = Datagram::decode(&buf).unwrap();
        assert_eq!(a, b);
        assert_eq!(used, buf.len());
    }

    #[test]
    fn datagram_truncated_header() {
        assert!(Datagram::decode(&[0, 1, 2]).is_err());
    }

    #[test]
    fn datagram_truncated_address() {
        // 8 байт заголовка + тип адреса без тела
        let mut buf = vec![0u8; 8];
        buf.push(0x01);
        assert!(Datagram::decode(&buf).is_err());
    }

    #[test]
    fn auth_response_error_preserves_message() {
        let a = AuthResponse::error("denied");
        assert_eq!(a.status, STATUS_ERR);
        let mut buf = Vec::new();
        a.encode(&mut buf);
        let (b, used) = AuthResponse::decode(&buf).unwrap();
        assert_eq!(a, b);
        assert_eq!(used, buf.len());
        assert_eq!(b.message, b"denied");
    }

    #[test]
    fn auth_request_with_padding_roundtrip() {
        let mut a = AuthRequest::new_password(b"pw", 1_000, FEATURE_UDP);
        a.padding = vec![7u8; 50];
        let mut buf = Vec::new();
        a.encode(&mut buf);
        let (b, used) = AuthRequest::decode(&buf).unwrap();
        assert_eq!(a, b);
        assert_eq!(used, buf.len());
    }

    #[test]
    fn open_stream_ack_with_message_roundtrip() {
        let a = OpenStreamAck {
            status: STATUS_ERR,
            error_code: ERR_CONNECT_FAILED,
            message: b"no route".to_vec(),
        };
        let mut buf = Vec::new();
        a.encode(&mut buf);
        let (b, used) = OpenStreamAck::decode(&buf).unwrap();
        assert_eq!(a, b);
        assert_eq!(used, buf.len());
    }

    #[test]
    fn auth_request_carries_nonce_and_proof_not_password() {
        let a = AuthRequest::new_password(b"super-secret", 0, FEATURE_UDP);
        assert_eq!(a.client_nonce.len(), NONCE_LEN);
        assert!(!a.auth_proof.is_empty());
        // сырой пароль не должен фигурировать в закодированном виде
        let mut buf = Vec::new();
        a.encode(&mut buf);
        assert!(!buf.windows(b"super-secret".len()).any(|w| w == b"super-secret"));
    }

    #[test]
    fn auth_proof_verifies_with_correct_password_only() {
        let nonce = [7u8; NONCE_LEN];
        let good = compute_auth_proof(b"pw", &nonce);
        let bad = compute_auth_proof(b"other", &nonce);
        assert_ne!(good, bad);
        assert!(ct_eq(&good, &good));
        assert!(!ct_eq(&good, &bad));
    }

    #[test]
    fn auth_proof_is_nonce_dependent() {
        let p1 = compute_auth_proof(b"pw", &[1u8; NONCE_LEN]);
        let p2 = compute_auth_proof(b"pw", &[2u8; NONCE_LEN]);
        assert_ne!(p1, p2, "доказательство должно зависеть от nonce");
    }

    #[test]
    fn auth_response_error_code_preserved() {
        let a = AuthResponse::error_with_code(ERR_RATE_LIMITED, "slow down");
        let mut buf = Vec::new();
        a.encode(&mut buf);
        let (b, _) = AuthResponse::decode(&buf).unwrap();
        assert_eq!(b.status, STATUS_ERR);
        assert_eq!(b.error_code, ERR_RATE_LIMITED);
        assert_eq!(b.message, b"slow down");
    }

    #[test]
    fn open_stream_ack_ok_has_zero_code() {
        let a = OpenStreamAck::ok();
        assert_eq!(a.status, STATUS_OK);
        assert_eq!(a.error_code, ERR_NONE);
    }

    #[test]
    fn random_padding_obeyed() {
        let mut state = 0u8;
        let mut f = || {
            state = state.wrapping_add(1);
            state
        };
        let p = random_padding(&mut f, 16);
        assert_eq!(p.len(), 16);
        // первый вызов даёт 1, далее 1..=16
        assert_eq!(p, (1u8..=16).collect::<Vec<_>>());
    }

    #[test]
    fn random_padding_zero_length() {
        let mut f = || 0u8;
        assert_eq!(random_padding(&mut f, 0).len(), 0);
    }
}

#[cfg(test)]
mod reader_tests {
    use super::*;

    #[test]
    fn reads_u8_varint_bytes_remaining() {
        let mut buf = Vec::new();
        buf.push(0xAA);
        encode_varint(&mut buf, 3);
        // поле `bytes` — длина + тело
        encode_varint(&mut buf, 3);
        buf.extend_from_slice(&[1, 2, 3]);
        buf.extend_from_slice(b"tail");

        let mut r = Reader::new(&buf);
        assert_eq!(r.u8().unwrap(), 0xAA);
        assert_eq!(r.varint().unwrap(), 3);
        assert_eq!(r.bytes().unwrap(), vec![1, 2, 3]);
        assert_eq!(r.remaining(), b"tail");
    }

    #[test]
    fn u8_truncated() {
        assert!(Reader::new(&[]).u8().is_err());
    }

    #[test]
    fn varint_truncated() {
        assert!(Reader::new(&[0x40]).varint().is_err());
    }

    #[test]
    fn bytes_truncated() {
        // заявлена длина 5, но данных 2
        let mut buf = Vec::new();
        encode_varint(&mut buf, 5);
        buf.extend_from_slice(&[1, 2]);
        assert!(Reader::new(&buf).bytes().is_err());
    }
}