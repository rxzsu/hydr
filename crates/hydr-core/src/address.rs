use crate::error::{Error, Result};
use crate::varint::encode_varint;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Address {
    Ip(IpAddr, u16),
    Domain(String, u16),
}

impl Address {
    pub fn port(&self) -> u16 {
        match self {
            Address::Ip(_, p) | Address::Domain(_, p) => *p,
        }
    }

    pub fn hostname(&self) -> String {
        match self {
            Address::Ip(ip, _) => ip.to_string(),
            Address::Domain(d, _) => d.clone(),
        }
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        match self {
            Address::Ip(IpAddr::V4(ip), port) => {
                buf.push(0x01);
                buf.extend_from_slice(&ip.octets());
                buf.extend_from_slice(&port.to_be_bytes());
            }
            Address::Ip(IpAddr::V6(ip), port) => {
                buf.push(0x02);
                buf.extend_from_slice(&ip.octets());
                buf.extend_from_slice(&port.to_be_bytes());
            }
            Address::Domain(d, port) => {
                buf.push(0x03);
                encode_varint(buf, d.len() as u64);
                buf.extend_from_slice(d.as_bytes());
                buf.extend_from_slice(&port.to_be_bytes());
            }
        }
    }

    pub fn decode(buf: &[u8]) -> Result<(Address, usize)> {
        let &ty = buf.first().ok_or(Error::UnexpectedEof)?;
        match ty {
            0x01 => {
                if buf.len() < 7 {
                    return Err(Error::UnexpectedEof);
                }
                let mut octets = [0u8; 4];
                octets.copy_from_slice(&buf[1..5]);
                let port = u16::from_be_bytes([buf[5], buf[6]]);
                Ok((Address::Ip(IpAddr::V4(Ipv4Addr::from(octets)), port), 7))
            }
            0x02 => {
                if buf.len() < 19 {
                    return Err(Error::UnexpectedEof);
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&buf[1..17]);
                let port = u16::from_be_bytes([buf[17], buf[18]]);
                Ok((Address::Ip(IpAddr::V6(Ipv6Addr::from(octets)), port), 19))
            }
            0x03 => {
                let (len, used) = crate::varint::decode_varint(&buf[1..])?;
                let len = len as usize;
                let start = 1 + used;
                if buf.len() < start + len + 2 {
                    return Err(Error::UnexpectedEof);
                }
                let domain =
                    String::from_utf8_lossy(&buf[start..start + len]).to_string();
                let port = u16::from_be_bytes([
                    buf[start + len],
                    buf[start + len + 1],
                ]);
                Ok((Address::Domain(domain, port), start + len + 2))
            }
            _ => Err(Error::InvalidData("bad address type")),
        }
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Address::Ip(ip, p) => write!(f, "{ip}:{p}"),
            Address::Domain(d, p) => write!(f, "{d}:{p}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_ipv4() {
        let a = Address::Ip("10.0.0.1".parse().unwrap(), 443);
        let mut buf = Vec::new();
        a.encode(&mut buf);
        let (b, used) = Address::decode(&buf).unwrap();
        assert_eq!(a, b);
        assert_eq!(used, buf.len());
    }

    #[test]
    fn roundtrip_ipv6() {
        let a = Address::Ip("::1".parse().unwrap(), 53);
        let mut buf = Vec::new();
        a.encode(&mut buf);
        let (b, used) = Address::decode(&buf).unwrap();
        assert_eq!(a, b);
        assert_eq!(used, buf.len());
    }

    #[test]
    fn roundtrip_domain() {
        let a = Address::Domain("example.com".into(), 8080);
        let mut buf = Vec::new();
        a.encode(&mut buf);
        let (b, used) = Address::decode(&buf).unwrap();
        assert_eq!(a, b);
        assert_eq!(used, buf.len());
    }
}