pub mod quic;
pub mod tls;
pub mod ws;

use hydr_core::message::{OpenStream, OpenStreamAck, ERR_NONE, STATUS_ERR};
use hydr_core::{Address, Datagram, Error, Result};
pub use quic::{DynStream, ProxyStream, QuicTunnel};
pub use ws::{IncomingOpen, WsEvent, WsHandle, WsTunnel};

pub enum Tunnel {
    Quic(QuicTunnel),
    Ws(WsTunnel),
}

#[derive(Clone)]
pub enum TunnelHandle {
    Quic(quinn::Connection),
    Ws(WsHandle),
}

impl TunnelHandle {
    pub fn from_tunnel(t: &Tunnel) -> Self {
        match t {
            Tunnel::Quic(q) => TunnelHandle::Quic(q.connection().clone()),
            Tunnel::Ws(w) => TunnelHandle::Ws(w.handle()),
        }
    }

    pub async fn open_stream(&self, addr: &Address) -> Result<DynStream> {
        match self {
            TunnelHandle::Quic(conn) => {
                let (mut send, mut recv) = conn.open_bi().await.map_err(quic::to_io_error)?;
                let mut buf = Vec::new();
                OpenStream { address: addr.clone() }.encode(&mut buf);
                quic::write_len_prefixed(&mut send, &buf).await?;
                let ack = quic::read_message(&mut recv, OpenStreamAck::decode).await?;
                if ack.status == STATUS_ERR {
                    return Err(Error::Message(format!(
                        "[code {}] {}",
                        ack.error_code,
                        String::from_utf8_lossy(&ack.message)
                    )));
                }
                Ok(Box::new(quic::QuicStream { send, recv }))
            }
            TunnelHandle::Ws(h) => h.open_stream(addr).await,
        }
    }

    pub fn send_datagram(&self, dg: &Datagram) -> Result<()> {
        match self {
            TunnelHandle::Quic(conn) => {
                let mut buf = Vec::new();
                dg.encode(&mut buf);
                conn.send_datagram(buf.into()).map_err(quic::to_io_error)
            }
            TunnelHandle::Ws(h) => h.send_datagram(dg),
        }
    }

    /// Закрывает соединение, не трогая владеющий туннель (безопасно для
    /// вызова из сервисных циклов, не держащих мьютекс).
    pub fn close(&self) {
        match self {
            TunnelHandle::Quic(conn) => {
                conn.close(quinn::VarInt::from_u32(0), b"bye");
            }
            TunnelHandle::Ws(h) => {
                let _ = h.close();
            }
        }
    }
}

pub enum ServerEvent {
    Stream(AcceptedStream),
    Datagram(Datagram),
}

pub struct AcceptedStream {
    pub address: Address,
    inner: AcceptedInner,
}

enum AcceptedInner {
    Quic {
        send: quinn::SendStream,
        recv: quinn::RecvStream,
    },
    Ws {
        cmd: tokio::sync::mpsc::Sender<ws::Cmd>,
        id: u64,
        a_read: Option<ws::WsRead>,
        a_write: Option<ws::WsWrite>,
        b_read: ws::WsRead,
        b_write: ws::WsWrite,
    },
}

impl AcceptedStream {
    pub async fn reply(&mut self, status: u8, message: &[u8]) -> Result<()> {
        self.reply_with_code(status, ERR_NONE, message).await
    }

    pub async fn reply_with_code(
        &mut self,
        status: u8,
        error_code: u8,
        message: &[u8],
    ) -> Result<()> {
        match &mut self.inner {
            AcceptedInner::Quic { send, .. } => {
                let mut buf = Vec::new();
                OpenStreamAck {
                    status,
                    error_code,
                    message: message.to_vec(),
                }
                .encode(&mut buf);
                crate::quic::write_len_prefixed(send, &buf).await
            }
            AcceptedInner::Ws {
                cmd,
                id,
                a_read,
                a_write,
                ..
            } => {
                let a_read = a_read.take().ok_or(hydr_core::Error::StreamClosed)?;
                let a_write = a_write.take().ok_or(hydr_core::Error::StreamClosed)?;
                ws::reply_open(cmd, *id, status, error_code, message.to_vec(), a_read, a_write).await
            }
        }
    }

    pub fn into_relay(self) -> DynStream {
        match self.inner {
            AcceptedInner::Quic { send, recv } => Box::new(quic::QuicStream { send, recv }),
            AcceptedInner::Ws {
                b_read, b_write, ..
            } => Box::new(ws::DuplexIo {
                r: b_read,
                w: b_write,
            }),
        }
    }
}

impl Tunnel {
    pub async fn open_stream(&self, addr: &Address) -> Result<DynStream> {
        match self {
            Tunnel::Quic(t) => t.open_stream(addr).await,
            Tunnel::Ws(t) => t.open_stream(addr).await,
        }
    }

    pub fn send_datagram(&self, dg: &Datagram) -> Result<()> {
        match self {
            Tunnel::Quic(t) => t.send_datagram(dg),
            Tunnel::Ws(t) => t.send_datagram(dg),
        }
    }

    pub async fn recv_datagram(&mut self) -> Result<Datagram> {
        match self {
            Tunnel::Quic(t) => t.recv_datagram().await,
            Tunnel::Ws(t) => t.recv_datagram().await,
        }
    }

    pub async fn accept_stream(&mut self) -> Result<AcceptedStream> {
        match self {
            Tunnel::Quic(t) => {
                let acc = t.accept_stream().await?;
                Ok(AcceptedStream {
                    address: acc.address,
                    inner: AcceptedInner::Quic {
                        send: acc.send,
                        recv: acc.recv,
                    },
                })
            }
            Tunnel::Ws(t) => {
                let inc = t.accept_stream().await?;
                Ok(self.ws_accepted(inc))
            }
        }
    }

    pub async fn next_event(&mut self) -> Result<ServerEvent> {
        match self {
            Tunnel::Quic(t) => tokio::select! {
                r = t.accept_stream() => {
                    let acc = r?;
                    Ok(ServerEvent::Stream(AcceptedStream {
                        address: acc.address,
                        inner: AcceptedInner::Quic { send: acc.send, recv: acc.recv },
                    }))
                }
                r = t.recv_datagram() => Ok(ServerEvent::Datagram(r?)),
            },
            Tunnel::Ws(t) => match t.next_event().await? {
                WsEvent::Open(inc) => Ok(ServerEvent::Stream(self.ws_accepted(inc))),
                WsEvent::Datagram(d) => Ok(ServerEvent::Datagram(d)),
            },
        }
    }

    fn ws_accepted(&self, inc: IncomingOpen) -> AcceptedStream {
        AcceptedStream {
            address: inc.address,
            inner: AcceptedInner::Ws {
                cmd: match self {
                    Tunnel::Ws(t) => t.handle.cmd.clone(),
                    Tunnel::Quic(_) => unreachable!(),
                },
                id: inc.stream_id,
                a_read: Some(inc.a_read),
                a_write: Some(inc.a_write),
                b_read: inc.b_read,
                b_write: inc.b_write,
            },
        }
    }

    pub async fn close(&self) {
        match self {
            Tunnel::Quic(t) => t.close().await,
            Tunnel::Ws(t) => t.close().await,
        }
    }
}