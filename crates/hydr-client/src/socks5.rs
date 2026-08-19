use hydr_core::{Address, Error, Result};
use tokio::io::{AsyncRead, AsyncReadExt};

pub const CMD_CONNECT: u8 = 0x01;
pub const CMD_UDP_ASSOCIATE: u8 = 0x03;

pub struct Request {
    pub cmd: u8,
    pub address: Address,
}

pub async fn read_request(r: &mut (impl AsyncRead + Unpin)) -> Result<Request> {
    let mut head = [0u8; 4];
    r.read_exact(&mut head).await?;
    if head[0] != 5 {
        return Err(Error::InvalidData("bad socks version"));
    }
    let cmd = head[1];
    let atyp = head[3];
    let mut addr = vec![0u8; 1];
    addr[0] = atyp;
    match atyp {
        1 => {
            let mut rest = [0u8; 6];
            r.read_exact(&mut rest).await?;
            addr.extend_from_slice(&rest);
        }
        4 => {
            let mut rest = [0u8; 18];
            r.read_exact(&mut rest).await?;
            addr.extend_from_slice(&rest);
        }
        3 => {
            let mut len = [0u8; 1];
            r.read_exact(&mut len).await?;
            addr.push(len[0]);
            let mut rest = vec![0u8; len[0] as usize + 2];
            r.read_exact(&mut rest).await?;
            addr.extend_from_slice(&rest);
        }
        _ => return Err(Error::InvalidData("bad address type")),
    }
    let (address, _) = Address::decode(&addr)?;
    Ok(Request { cmd, address })
}

pub fn parse_udp_packet(buf: &[u8]) -> Result<(Address, &[u8])> {
    if buf.len() < 4 || buf[2] != 0 {
        return Err(Error::InvalidData("bad socks udp header"));
    }
    let (address, used) = Address::decode(&buf[3..])?;
    Ok((address, &buf[3 + used..]))
}