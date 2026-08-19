use crate::error::{Error, Result};
use crate::varint::{encode_varint, MAX_VARINT};

pub const FRAME_OPEN_STREAM: u8 = 0x01;
pub const FRAME_OPEN_STREAM_ACK: u8 = 0x02;
pub const FRAME_STREAM_DATA: u8 = 0x03;
pub const FRAME_STREAM_CLOSE: u8 = 0x04;
pub const FRAME_DATAGRAM: u8 = 0x05;
pub const FRAME_PING: u8 = 0x06;
pub const FRAME_PONG: u8 = 0x07;
pub const FRAME_AUTH_REQUEST: u8 = 0x08;
pub const FRAME_AUTH_RESPONSE: u8 = 0x09;
pub const FRAME_SESSION_CLOSE: u8 = 0x0a;

pub const CONTROL_STREAM: u64 = 0;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub stream_id: u64,
    pub frame_type: u8,
    pub body: Vec<u8>,
}

impl Frame {
    pub fn new(stream_id: u64, frame_type: u8, body: Vec<u8>) -> Self {
        Self {
            stream_id,
            frame_type,
            body,
        }
    }

    pub fn data(stream_id: u64, body: Vec<u8>) -> Self {
        Self::new(stream_id, FRAME_STREAM_DATA, body)
    }

    pub fn ping() -> Self {
        Self::new(CONTROL_STREAM, FRAME_PING, Vec::new())
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        encode_varint(buf, self.stream_id);
        buf.push(self.frame_type);
        encode_varint(buf, self.body.len() as u64);
        buf.extend_from_slice(&self.body);
    }

    pub fn decode(buf: &[u8]) -> Result<(Frame, usize)> {
        let (stream_id, used) = crate::varint::decode_varint(buf)?;
        let mut pos = used;
        let frame_type = *buf.get(pos).ok_or(Error::UnexpectedEof)?;
        pos += 1;
        let (body_len, used2) = crate::varint::decode_varint(&buf[pos..])?;
        pos += used2;
        let body_len = body_len as usize;
        if buf.len() < pos + body_len {
            return Err(Error::UnexpectedEof);
        }
        let body = buf[pos..pos + body_len].to_vec();
        Ok((
            Frame {
                stream_id,
                frame_type,
                body,
            },
            pos + body_len,
        ))
    }
}

pub fn max_frame_len() -> usize {
    MAX_VARINT + 1 + MAX_VARINT + 64 * 1024
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_roundtrip() {
        for f in [
            Frame::ping(),
            Frame::data(42, vec![0; 1024]),
            Frame::new(1, FRAME_OPEN_STREAM, vec![1, 2, 3]),
        ] {
            let mut buf = Vec::new();
            f.encode(&mut buf);
            let (d, used) = Frame::decode(&buf).unwrap();
            assert_eq!(f, d);
            assert_eq!(used, buf.len());
        }
    }
}