use crate::address::Address;
use crate::error::{Error, Result};
use crate::varint::encode_varint;
use std::collections::VecDeque;

pub const PROTOCOL_VERSION: u64 = 0x01;
pub const STATUS_OK: u8 = 0x00;
pub const STATUS_ERR: u8 = 0x01;

pub const FEATURE_UDP: u8 = 0x01;
pub const FEATURE_MUX: u8 = 0x02;

pub fn random_padding(rng: &mut impl FnMut() -> u8, len: usize) -> Vec<u8> {
    (0..len).map(|_| rng()).collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthRequest {
    pub version: u64,
    pub auth_method: u8,
    pub auth: Vec<u8>,
    pub cc_rx: u64,
    pub features: u8,
    pub padding: Vec<u8>,
}

impl AuthRequest {
    pub const AUTH_PASSWORD: u8 = 0x01;

    pub fn new_password(password: &[u8], cc_rx: u64, features: u8) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            auth_method: Self::AUTH_PASSWORD,
            auth: password.to_vec(),
            cc_rx,
            features,
            padding: Vec::new(),
        }
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        encode_varint(buf, self.version);
        buf.push(self.auth_method);
        encode_varint(buf, self.auth.len() as u64);
        buf.extend_from_slice(&self.auth);
        encode_varint(buf, self.cc_rx);
        buf.push(self.features);
        encode_varint(buf, self.padding.len() as u64);
        buf.extend_from_slice(&self.padding);
    }

    pub fn decode(buf: &[u8]) -> Result<(AuthRequest, usize)> {
        let mut rd = Reader::new(buf);
        let version = rd.varint()?;
        let auth_method = rd.u8()?;
        let auth = rd.bytes()?;
        let cc_rx = rd.varint()?;
        let features = rd.u8()?;
        let padding = rd.bytes()?;
        Ok((
            AuthRequest {
                version,
                auth_method,
                auth,
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
    pub message: Vec<u8>,
    pub server_cc_rx: u64,
    pub server_features: u8,
    pub padding: Vec<u8>,
}

impl AuthResponse {
    pub fn ok(server_cc_rx: u64, server_features: u8) -> Self {
        Self {
            status: STATUS_OK,
            message: Vec::new(),
            server_cc_rx,
            server_features,
            padding: Vec::new(),
        }
    }

    pub fn error(msg: &str) -> Self {
        Self {
            status: STATUS_ERR,
            message: msg.as_bytes().to_vec(),
            server_cc_rx: 0,
            server_features: 0,
            padding: Vec::new(),
        }
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.push(self.status);
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
        let message = rd.bytes()?;
        let server_cc_rx = rd.varint()?;
        let server_features = rd.u8()?;
        let padding = rd.bytes()?;
        Ok((
            AuthResponse {
                status,
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
    pub message: Vec<u8>,
}

impl OpenStreamAck {
    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.push(self.status);
        encode_varint(buf, self.message.len() as u64);
        buf.extend_from_slice(&self.message);
    }

    pub fn decode(buf: &[u8]) -> Result<(OpenStreamAck, usize)> {
        let mut rd = Reader::new(buf);
        let status = rd.u8()?;
        let message = rd.bytes()?;
        Ok((OpenStreamAck { status, message }, rd.pos))
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
        let a = AuthRequest::new_password(b"secret", 100_000, FEATURE_UDP | FEATURE_MUX);
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
}