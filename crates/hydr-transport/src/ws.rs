use std::collections::HashMap;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use futures_util::{SinkExt, StreamExt};
use hydr_core::frame::{
    Frame, FRAME_AUTH_REQUEST, FRAME_AUTH_RESPONSE, FRAME_DATAGRAM, FRAME_OPEN_STREAM,
    FRAME_OPEN_STREAM_ACK, FRAME_PING, FRAME_PONG, FRAME_STREAM_CLOSE, FRAME_STREAM_DATA,
};
use hydr_core::message::{AuthRequest, AuthResponse, Datagram, OpenStream, OpenStreamAck, STATUS_OK};
use hydr_core::obfuscation::Obfuscator;
use hydr_core::{Address, Error, Result};
use tokio::io::{
    AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf, ReadHalf, WriteHalf,
};
use tokio::sync::{mpsc, oneshot};
use tokio_tungstenite::tungstenite::http::Response as HttpResponse;
use tokio_tungstenite::tungstenite::{Bytes, Message};
use tokio_tungstenite::WebSocketStream;

use crate::quic::{DynStream, ProxyStream};

pub type WsRead = ReadHalf<DuplexStream>;
pub type WsWrite = WriteHalf<DuplexStream>;

#[derive(Clone)]
pub struct WsHandle {
    pub(crate) cmd: mpsc::Sender<Cmd>,
    next_stream_id: Arc<AtomicU64>,
}

impl WsHandle {
    pub async fn open_stream(&self, addr: &Address) -> Result<DynStream> {
        let id = self.next_stream_id.fetch_add(1, Ordering::Relaxed) + 1;
        let (a, b) = tokio::io::duplex(64 * 1024);
        let (b_read, b_write) = tokio::io::split(b);
        let (a_read, a_write) = tokio::io::split(a);
        let (ack_tx, ack_rx) = oneshot::channel();
        self.cmd
            .send(Cmd::Open {
                id,
                addr: addr.clone(),
                a_read,
                a_write,
                ack: ack_tx,
            })
            .await
            .map_err(|_| Error::StreamClosed)?;
        ack_rx.await.map_err(|_| Error::StreamClosed)??;
        Ok(Box::new(DuplexIo { r: b_read, w: b_write }))
    }

    pub fn send_datagram(&self, dg: &Datagram) -> Result<()> {
        let mut body = Vec::new();
        dg.encode(&mut body);
        let frame = Frame::new(0, FRAME_DATAGRAM, body);
        let _ = self.cmd.try_send(Cmd::SendFrame(frame));
        Ok(())
    }

    /// Закрывает WS-соединение (останавливает цикл `run`).
    pub fn close(&self) -> Result<()> {
        self.cmd.try_send(Cmd::Close).map_err(|_| Error::StreamClosed)
    }
}

pub struct WsTunnel {
    pub(crate) handle: WsHandle,
    event_rx: mpsc::Receiver<WsEvent>,
}

pub enum WsEvent {
    Open(IncomingOpen),
    Datagram(Datagram),
}

pub struct IncomingOpen {
    pub stream_id: u64,
    pub address: Address,
    pub a_read: WsRead,
    pub a_write: WsWrite,
    pub b_read: WsRead,
    pub b_write: WsWrite,
}

pub(crate) enum Cmd {
    SendFrame(Frame),
    Open {
        id: u64,
        addr: Address,
        a_read: WsRead,
        a_write: WsWrite,
        ack: oneshot::Sender<Result<()>>,
    },
    ReplyOpen {
        id: u64,
        status: u8,
        message: Vec<u8>,
        a_read: WsRead,
        a_write: WsWrite,
    },
    Close,
}

struct PendingOpen {
    a_read: WsRead,
    a_write: WsWrite,
    ack: oneshot::Sender<Result<()>>,
}

impl WsTunnel {
    fn new(cmd: mpsc::Sender<Cmd>, event_rx: mpsc::Receiver<WsEvent>) -> Self {
        Self {
            handle: WsHandle {
                cmd: cmd.clone(),
                next_stream_id: Arc::new(AtomicU64::new(0)),
            },
            event_rx,
        }
    }

    pub fn handle(&self) -> WsHandle {
        self.handle.clone()
    }

    pub async fn open_stream(&self, addr: &Address) -> Result<DynStream> {
        self.handle.open_stream(addr).await
    }

    pub fn send_datagram(&self, dg: &Datagram) -> Result<()> {
        self.handle.send_datagram(dg)
    }

    pub async fn next_event(&mut self) -> Result<WsEvent> {
        self.event_rx.recv().await.ok_or(Error::StreamClosed)
    }

    pub async fn accept_stream(&mut self) -> Result<IncomingOpen> {
        loop {
            match self.next_event().await? {
                WsEvent::Open(o) => return Ok(o),
                WsEvent::Datagram(_) => continue,
            }
        }
    }

    pub async fn recv_datagram(&mut self) -> Result<Datagram> {
        loop {
            match self.next_event().await? {
                WsEvent::Datagram(d) => return Ok(d),
                WsEvent::Open(_) => continue,
            }
        }
    }

    pub async fn close(&self) {
        let _ = self
            .handle
            .cmd
            .send(Cmd::SendFrame(Frame::new(0, FRAME_STREAM_CLOSE, vec![])))
            .await;
    }
}

pub struct DuplexIo {
    pub(crate) r: WsRead,
    pub(crate) w: WsWrite,
}

impl ProxyStream for DuplexIo {}

impl AsyncRead for DuplexIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.r).poll_read(cx, buf)
    }
}

impl AsyncWrite for DuplexIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.w).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.w).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.w).poll_shutdown(cx)
    }
}

fn encode_frame(f: &Frame) -> Vec<u8> {
    let mut buf = Vec::new();
    f.encode(&mut buf);
    buf
}

fn outbound(f: &Frame, ob: &Option<Arc<Obfuscator>>) -> Message {
    let mut b = encode_frame(f);
    if let Some(ob) = ob {
        ob.encrypt(&mut b);
    }
    Message::Binary(Bytes::from(b))
}

fn inbound(bytes: &[u8], ob: &Option<Arc<Obfuscator>>) -> Vec<u8> {
    match ob {
        Some(ob) => ob.decrypt(bytes).unwrap_or_default(),
        None => bytes.to_vec(),
    }
}

async fn pump_stream(cmd_tx: mpsc::Sender<Cmd>, id: u64, mut a_read: WsRead) {
    let mut buf = [0u8; 32 * 1024];
    loop {
        match a_read.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => {
                let f = Frame::data(id, buf[..n].to_vec());
                if cmd_tx.send(Cmd::SendFrame(f)).await.is_err() {
                    return;
                }
            }
            Err(_) => break,
        }
    }
    let _ = cmd_tx
        .send(Cmd::SendFrame(Frame::new(id, FRAME_STREAM_CLOSE, vec![])))
        .await;
}

type ServerValidator = Arc<dyn Fn(&AuthRequest) -> Result<AuthResponse> + Send + Sync>;

pub(crate) async fn reply_open(
    cmd: &mpsc::Sender<Cmd>,
    id: u64,
    status: u8,
    message: Vec<u8>,
    a_read: WsRead,
    a_write: WsWrite,
) -> Result<()> {
    cmd.send(Cmd::ReplyOpen {
        id,
        status,
        message,
        a_read,
        a_write,
    })
    .await
    .map_err(|_| Error::StreamClosed)
}

pub async fn connect(url: &str, insecure: bool, auth: &AuthRequest) -> Result<WsTunnel> {
    connect_with_obfuscation(url, insecure, auth, None).await
}

pub async fn connect_with_obfuscation(
    url: &str,
    insecure: bool,
    auth: &AuthRequest,
    obfuscation: Option<Arc<Obfuscator>>,
) -> Result<WsTunnel> {
    let ws = if url.starts_with("wss://") {
        let cfg = crate::tls::make_client_config(insecure);
        tokio_tungstenite::connect_async_tls_with_config(
            url,
            None,
            true,
            Some(tokio_tungstenite::Connector::Rustls(cfg)),
        )
        .await
    } else {
        tokio_tungstenite::connect_async(url).await
    };
    let (ws, _) = ws.map_err(|e| Error::Io(std::io::Error::other(e.to_string())))?;

    let (cmd_tx, cmd_rx) = mpsc::channel(1024);
    let (event_tx, event_rx) = mpsc::channel(1024);
    let (auth_tx, auth_rx) = oneshot::channel();

    let tunnel = WsTunnel::new(cmd_tx.clone(), event_rx);
    tokio::spawn(run(
        ws,
        cmd_rx,
        event_tx,
        Some(auth_tx),
        None,
        cmd_tx.clone(),
        obfuscation,
    ));

    let mut buf = Vec::new();
    auth.encode(&mut buf);
    tunnel
        .handle
        .cmd
        .send(Cmd::SendFrame(Frame::new(0, FRAME_AUTH_REQUEST, buf)))
        .await
        .map_err(|_| Error::StreamClosed)?;

    let resp = auth_rx.await.map_err(|_| Error::StreamClosed)??;
    if resp.status != STATUS_OK {
        return Err(Error::Message(
            String::from_utf8_lossy(&resp.message).to_string(),
        ));
    }
    Ok(tunnel)
}

pub async fn accept(
    tcp: tokio::net::TcpStream,
    path: &str,
    validate: ServerValidator,
) -> Result<(WsTunnel, AuthRequest)> {
    accept_with_obfuscation(tcp, path, validate, None).await
}

pub async fn accept_with_obfuscation(
    tcp: tokio::net::TcpStream,
    path: &str,
    validate: ServerValidator,
    obfuscation: Option<Arc<Obfuscator>>,
) -> Result<(WsTunnel, AuthRequest)> {
    let ws = tokio_tungstenite::accept_hdr_async(
        tcp,
        move |req: &tokio_tungstenite::tungstenite::http::Request<()>,
              resp: tokio_tungstenite::tungstenite::http::Response<()>|
              -> std::result::Result<
                tokio_tungstenite::tungstenite::http::Response<()>,
                tokio_tungstenite::tungstenite::http::Response<Option<String>>,
              > {
            if !path.is_empty() && req.uri().path() != path {
                return Err(HttpResponse::new(Some("Forbidden".into())));
            }
            Ok(resp)
        },
    )
    .await
    .map_err(|e| Error::Io(std::io::Error::other(e.to_string())))?;

    let (cmd_tx, cmd_rx) = mpsc::channel(1024);
    let (event_tx, event_rx) = mpsc::channel(1024);
    let (auth_tx, auth_rx) = oneshot::channel();

    let tunnel = WsTunnel::new(cmd_tx.clone(), event_rx);
    tokio::spawn(run(
        ws,
        cmd_rx,
        event_tx,
        None,
        Some((validate, auth_tx)),
        cmd_tx.clone(),
        obfuscation,
    ));

    let req = auth_rx.await.map_err(|_| Error::StreamClosed)??;
    Ok((tunnel, req))
}

async fn run<S: AsyncRead + AsyncWrite + Unpin>(
    ws: WebSocketStream<S>,
    mut cmd_rx: mpsc::Receiver<Cmd>,
    event_tx: mpsc::Sender<WsEvent>,
    mut auth_response: Option<oneshot::Sender<Result<AuthResponse>>>,
    mut server_auth: Option<(ServerValidator, oneshot::Sender<Result<AuthRequest>>)>,
    cmd_tx: mpsc::Sender<Cmd>,
    obfuscation: Option<Arc<Obfuscator>>,
) {
    let (mut sink, mut stream) = ws.split();
    let mut streams: HashMap<u64, WsWrite> = HashMap::new();
    let mut pending: HashMap<u64, PendingOpen> = HashMap::new();
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(30));

    loop {
        tokio::select! {
            Some(cmd) = cmd_rx.recv() => {
                let done = match cmd {
                    Cmd::SendFrame(f) => {
                        match sink.send(outbound(&f, &obfuscation)).await {
                            Ok(()) => true,
                            Err(_) => false,
                        }
                    }
                    Cmd::Open { id, addr, a_read, a_write, ack } => {
                        let mut body = Vec::new();
                        OpenStream { address: addr }.encode(&mut body);
                        let f = Frame::new(id, FRAME_OPEN_STREAM, body);
                        match sink.send(outbound(&f, &obfuscation)).await {
                            Ok(()) => {
                                pending.insert(id, PendingOpen { a_read, a_write, ack });
                                true
                            }
                            Err(_) => false,
                        }
                    }
                    Cmd::ReplyOpen { id, status, message, a_read, a_write } => {
                        let mut body = Vec::new();
                        OpenStreamAck { status, message }.encode(&mut body);
                        let f = Frame::new(id, FRAME_OPEN_STREAM_ACK, body);
                        match sink.send(outbound(&f, &obfuscation)).await {
                            Ok(()) => {
                                if status == STATUS_OK {
                                    let sid = id;
                                    tokio::spawn(pump_stream(cmd_tx.clone(), sid, a_read));
                                    streams.insert(sid, a_write);
                                }
                                true
                            }
                            Err(_) => false,
                        }
                    }
                    Cmd::Close => false,
                };
                if !done {
                    break;
                }
            }
            Some(msg) = stream.next() => {
                match msg {
                    Ok(Message::Binary(bytes)) => {
                        let bytes = inbound(&bytes, &obfuscation);
                        if handle_frame(&mut sink, &bytes, &mut streams, &mut pending, &mut auth_response, &mut server_auth, &event_tx, &cmd_tx, &obfuscation).await.is_err() {
                            break;
                        }
                    }
                    Ok(Message::Ping(payload)) => {
                        let _ = sink.send(Message::Pong(payload)).await;
                    }
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
            _ = tick.tick() => {
                let _ = sink.send(Message::Ping(Bytes::new())).await;
            }
        }
    }

    for (_, p) in pending {
        let _ = p.ack.send(Err(Error::StreamClosed));
    }
    if let Some(tx) = auth_response.take() {
        let _ = tx.send(Err(Error::StreamClosed));
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_frame<S: AsyncRead + AsyncWrite + Unpin>(
    sink: &mut futures_util::stream::SplitSink<WebSocketStream<S>, Message>,
    bytes: &[u8],
    streams: &mut HashMap<u64, WsWrite>,
    pending: &mut HashMap<u64, PendingOpen>,
    auth_response: &mut Option<oneshot::Sender<Result<AuthResponse>>>,
    server_auth: &mut Option<(ServerValidator, oneshot::Sender<Result<AuthRequest>>)>,
    event_tx: &mpsc::Sender<WsEvent>,
    cmd_tx: &mpsc::Sender<Cmd>,
    obfuscation: &Option<Arc<Obfuscator>>,
) -> Result<()> {
    let (frame, _) = Frame::decode(bytes)?;
    match frame.frame_type {
        FRAME_AUTH_REQUEST => {
            if let Some((validate, done)) = server_auth.take() {
                let resp = AuthRequest::decode(&frame.body)
                    .map(|(req, _)| {
                        let resp = validate(&req);
                        let _ = done.send(Ok(req));
                        resp
                    })
                    .unwrap_or_else(|_| Ok(AuthResponse::error("bad request")));
                let resp = resp.unwrap_or_else(|e| AuthResponse::error(&e.to_string()));
                let mut body = Vec::new();
                resp.encode(&mut body);
                let f = Frame::new(0, FRAME_AUTH_RESPONSE, body);
                sink.send(outbound(&f, obfuscation))
                    .await
                    .map_err(|e| Error::Io(std::io::Error::other(e.to_string())))?;
            }
        }
        FRAME_AUTH_RESPONSE => {
            if let Some(tx) = auth_response.take() {
                let resp = AuthResponse::decode(&frame.body).map(|(r, _)| r);
                let _ = tx.send(resp);
            }
        }
        FRAME_OPEN_STREAM => {
            if let Ok((req, _)) = OpenStream::decode(&frame.body) {
                let (a, b) = tokio::io::duplex(64 * 1024);
                let (a_read, a_write) = tokio::io::split(a);
                let (b_read, b_write) = tokio::io::split(b);
                let _ = event_tx
                    .send(WsEvent::Open(IncomingOpen {
                        stream_id: frame.stream_id,
                        address: req.address,
                        a_read,
                        a_write,
                        b_read,
                        b_write,
                    }))
                    .await;
            }
        }
        FRAME_OPEN_STREAM_ACK => {
            if let Some(p) = pending.remove(&frame.stream_id) {
                match OpenStreamAck::decode(&frame.body).map(|(a, _)| a) {
                    Ok(ack) if ack.status == STATUS_OK => {
                        let id = frame.stream_id;
                        tokio::spawn(pump_stream(cmd_tx.clone(), id, p.a_read));
                        streams.insert(id, p.a_write);
                        let _ = p.ack.send(Ok(()));
                    }
                    Ok(ack) => {
                        let _ = p.ack.send(Err(Error::Message(
                            String::from_utf8_lossy(&ack.message).to_string(),
                        )));
                    }
                    Err(e) => {
                        let _ = p.ack.send(Err(e));
                    }
                }
            }
        }
        FRAME_STREAM_DATA => {
            if let Some(w) = streams.get_mut(&frame.stream_id) {
                let _ = w.write_all(&frame.body).await;
            }
        }
        FRAME_STREAM_CLOSE => {
            if let Some(mut w) = streams.remove(&frame.stream_id) {
                let _ = w.shutdown().await;
            }
        }
        FRAME_DATAGRAM => {
            if let Ok((dg, _)) = Datagram::decode(&frame.body) {
                let _ = event_tx.send(WsEvent::Datagram(dg)).await;
            }
        }
        FRAME_PING => {
            sink.send(outbound(&Frame::new(0, FRAME_PONG, frame.body), obfuscation))
                .await
                .map_err(|e| Error::Io(std::io::Error::other(e.to_string())))?;
        }
        _ => {}
    }
    Ok(())
}