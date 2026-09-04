use hydr_core::{Address, Error, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const CMD_CONNECT: u8 = 0x01;
pub const CMD_UDP_ASSOCIATE: u8 = 0x03;

/// SOCKS5 методы аутентификации (RFC 1928): no-auth и username/password (RFC 1929).
pub const METHOD_NO_AUTH: u8 = 0x00;
pub const METHOD_USERPASS: u8 = 0x02;
pub const METHOD_NO_ACCEPTABLE: u8 = 0xFF;

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

/// Выбирает метод аутентификации SOCKS5: если на клиенте заданы credentials —
/// требуем `METHOD_USERPASS` (RFC 1929), иначе `METHOD_NO_AUTH`.
/// Возвращает выбранный метод; `None` — нет пересечения (ответ 0xFF уже послан).
pub async fn negotiate_method(
    io: &mut (impl AsyncRead + AsyncWrite + Unpin),
    require_auth: bool,
) -> Result<Option<u8>> {
    let mut head = [0u8; 2];
    io.read_exact(&mut head).await?;
    if head[0] != 5 {
        return Err(Error::InvalidData("bad socks version"));
    }
    let nmethods = head[1] as usize;
    if nmethods == 0 || nmethods > 32 {
        return Err(Error::InvalidData("bad nmethods"));
    }
    let mut methods = vec![0u8; nmethods];
    io.read_exact(&mut methods).await?;
    let want = if require_auth {
        METHOD_USERPASS
    } else {
        METHOD_NO_AUTH
    };
    if methods.contains(&want) {
        io.write_all(&[5, want]).await?;
        Ok(Some(want))
    } else {
        io.write_all(&[5, METHOD_NO_ACCEPTABLE]).await?;
        Ok(None)
    }
}

/// Читает и проверяет username/password (RFC 1929, версия суб-протокола 0x01).
/// Сравнение — constant-time, чтобы не течь по времени.
pub async fn verify_userpass(
    io: &mut (impl AsyncRead + AsyncWrite + Unpin),
    expected_user: &str,
    expected_pass: &str,
) -> Result<bool> {
    let mut head = [0u8; 2];
    io.read_exact(&mut head).await?;
    if head[0] != 1 {
        return Err(Error::InvalidData("bad userpass version"));
    }
    let ulen = head[1] as usize;
    if ulen == 0 || ulen > 255 {
        return Err(Error::InvalidData("bad username length"));
    }
    let mut user = vec![0u8; ulen];
    io.read_exact(&mut user).await?;
    let mut plen_buf = [0u8; 1];
    io.read_exact(&mut plen_buf).await?;
    let plen = plen_buf[0] as usize;
    if plen > 255 {
        return Err(Error::InvalidData("bad password length"));
    }
    let mut pass = vec![0u8; plen];
    io.read_exact(&mut pass).await?;
    let ok = hydr_core::message::ct_eq(&user, expected_user.as_bytes())
        && hydr_core::message::ct_eq(&pass, expected_pass.as_bytes());
    io.write_all(&[1, u8::from(!ok)]).await?;
    Ok(ok)
}
