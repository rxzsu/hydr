use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use hydr_core::message::{AuthRequest, AuthResponse, Datagram, OpenStream, OpenStreamAck, STATUS_ERR};
use hydr_core::{Address, Error, Result};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::tls;

pub fn to_io_error(e: impl std::fmt::Display) -> Error {
    Error::Io(std::io::Error::other(e.to_string()))
}

pub trait ProxyStream: AsyncRead + AsyncWrite + Send + Unpin {}
impl ProxyStream for QuicStream {}
impl ProxyStream for tokio::net::TcpStream {}

pub type DynStream = Box<dyn ProxyStream>;

pub struct QuicTunnel {
    conn: quinn::Connection,
    _endpoint: Option<quinn::Endpoint>,
}

impl QuicTunnel {
    pub fn new(conn: quinn::Connection) -> Self {
        Self {
            conn,
            _endpoint: None,
        }
    }

    fn with_endpoint(conn: quinn::Connection, endpoint: quinn::Endpoint) -> Self {
        Self {
            conn,
            _endpoint: Some(endpoint),
        }
    }

    pub fn connection(&self) -> &quinn::Connection {
        &self.conn
    }

    pub async fn open_stream(&self, addr: &Address) -> Result<DynStream> {
        let (mut send, mut recv) = self.conn.open_bi().await.map_err(to_io_error)?;
        let mut buf = Vec::new();
        OpenStream { address: addr.clone() }.encode(&mut buf);
        write_len_prefixed(&mut send, &buf).await?;

        let ack = read_message(&mut recv, OpenStreamAck::decode).await?;
        if ack.status == STATUS_ERR {
            return Err(Error::Message(
                String::from_utf8_lossy(&ack.message).to_string(),
            ));
        }
        Ok(Box::new(QuicStream { send, recv }))
    }

    pub fn send_datagram(&self, dg: &Datagram) -> Result<()> {
        let mut buf = Vec::new();
        dg.encode(&mut buf);
        self.conn
            .send_datagram(buf.into())
            .map_err(to_io_error)
    }

    pub async fn recv_datagram(&self) -> Result<Datagram> {
        let data = self.conn.read_datagram().await.map_err(to_io_error)?;
        Datagram::decode(&data).map(|(d, _)| d)
    }

    pub async fn close(&self) {
        self.conn.close(quinn::VarInt::from_u32(0), b"bye");
        self.conn.closed().await;
    }

    pub async fn accept_stream(&self) -> Result<QuicAccepted> {
        let (send, mut recv) = self.conn.accept_bi().await.map_err(to_io_error)?;
        let req = read_message(&mut recv, OpenStream::decode).await?;
        Ok(QuicAccepted {
            address: req.address,
            send,
            recv,
        })
    }
}

pub struct QuicAccepted {
    pub address: Address,
    pub send: quinn::SendStream,
    pub recv: quinn::RecvStream,
}

impl QuicAccepted {
    pub async fn ack(&mut self, status: u8, message: &[u8]) -> Result<()> {
        let mut buf = Vec::new();
        OpenStreamAck {
            status,
            message: message.to_vec(),
        }
        .encode(&mut buf);
        write_len_prefixed(&mut self.send, &buf).await?;
        Ok(())
    }
}

pub struct QuicStream {
    pub(crate) send: quinn::SendStream,
    pub(crate) recv: quinn::RecvStream,
}

impl AsyncRead for QuicStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for QuicStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.send)
            .poll_write(cx, buf)
            .map(|r| r.map_err(|e| std::io::Error::other(e.to_string())))
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.send)
            .poll_flush(cx)
            .map(|r| r.map_err(|e| std::io::Error::other(e.to_string())))
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.send)
            .poll_shutdown(cx)
            .map(|r| r.map_err(|e| std::io::Error::other(e.to_string())))
    }
}

pub async fn read_varint(recv: &mut quinn::RecvStream) -> Result<u64> {
    let mut first = [0u8; 1];
    recv.read_exact(&mut first).await.map_err(to_io_error)?;
    let tag = first[0] >> 6;
    let len = 1usize << tag;
    let mut buf = vec![0u8; len];
    buf[0] = first[0];
    if len > 1 {
        recv.read_exact(&mut buf[1..]).await.map_err(to_io_error)?;
    }
    let (v, _) = hydr_core::varint::decode_varint(&buf)?;
    Ok(v)
}

pub async fn write_varint(send: &mut quinn::SendStream, v: u64) -> Result<()> {
    let mut buf = Vec::new();
    hydr_core::varint::encode_varint(&mut buf, v);
    send.write_all(&buf).await.map_err(to_io_error)?;
    Ok(())
}

pub async fn read_message<T>(
    recv: &mut quinn::RecvStream,
    decode: impl Fn(&[u8]) -> Result<(T, usize)>,
) -> Result<T> {
    let len = read_varint(recv).await?;
    let mut buf = vec![0u8; len as usize];
    recv.read_exact(&mut buf).await.map_err(to_io_error)?;
    let (msg, _used) = decode(&buf)?;
    Ok(msg)
}

pub async fn write_len_prefixed(send: &mut quinn::SendStream, buf: &[u8]) -> Result<()> {
    write_varint(send, buf.len() as u64).await?;
    send.write_all(buf).await.map_err(to_io_error)?;
    Ok(())
}

pub async fn client_handshake(
    endpoint: quinn::Endpoint,
    conn: quinn::Connection,
    auth: &AuthRequest,
) -> Result<QuicTunnel> {
    let (mut send, mut recv) = conn.open_bi().await.map_err(to_io_error)?;
    let mut buf = Vec::new();
    auth.encode(&mut buf);
    write_len_prefixed(&mut send, &buf).await?;

    let resp = read_message(&mut recv, AuthResponse::decode).await?;
    if resp.status == STATUS_ERR {
        return Err(Error::Message(
            String::from_utf8_lossy(&resp.message).to_string(),
        ));
    }
    Ok(QuicTunnel::with_endpoint(conn, endpoint))
}

pub async fn server_handshake(
    conn: quinn::Connection,
    validate: impl Fn(&AuthRequest) -> Result<AuthResponse>,
) -> Result<(QuicTunnel, AuthRequest)> {
    let (mut send, mut recv) = conn.accept_bi().await.map_err(to_io_error)?;
    let req = read_message(&mut recv, AuthRequest::decode).await?;
    let resp = validate(&req)?;
    let mut buf = Vec::new();
    resp.encode(&mut buf);
    write_len_prefixed(&mut send, &buf).await?;
    Ok((QuicTunnel::new(conn), req))
}

pub fn default_transport_config() -> quinn::TransportConfig {
    let mut cfg = quinn::TransportConfig::default();
    cfg.max_concurrent_bidi_streams(1024u32.into());
    cfg.keep_alive_interval(Some(std::time::Duration::from_secs(5)));
    cfg
}

pub fn make_server_config(
    rustls_cfg: rustls::ServerConfig,
    transport: Option<quinn::TransportConfig>,
) -> Result<quinn::ServerConfig> {
    let quic_cfg = quinn::crypto::rustls::QuicServerConfig::try_from(rustls_cfg)
        .map_err(to_io_error)?;
    let mut cfg = quinn::ServerConfig::with_crypto(Arc::new(quic_cfg));
    if let Some(t) = transport {
        cfg.transport_config(Arc::new(t));
    }
    Ok(cfg)
}

pub async fn connect(
    addr: SocketAddr,
    server_name: &str,
    insecure: bool,
    transport: Option<quinn::TransportConfig>,
    auth: &AuthRequest,
) -> Result<QuicTunnel> {
    let rustls_cfg = tls::make_client_config(insecure);
    let quic_cfg = quinn::crypto::rustls::QuicClientConfig::try_from(rustls_cfg)
        .map_err(to_io_error)?;
    let mut quinn_cfg = quinn::ClientConfig::new(Arc::new(quic_cfg));
    if let Some(t) = transport {
        quinn_cfg.transport_config(Arc::new(t));
    }
    let endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap())?;
    let conn = endpoint
        .connect_with(quinn_cfg, addr, server_name)
        .map_err(to_io_error)?
        .await
        .map_err(to_io_error)?;
    client_handshake(endpoint, conn, auth).await
}