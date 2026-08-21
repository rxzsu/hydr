use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use hydr_core::message::{
    compute_auth_proof, ct_eq, AuthRequest, AuthResponse, Datagram, ERR_BAD_CREDENTIALS,
    ERR_CONNECT_FAILED, ERR_PROTOCOL, ERR_UNSUPPORTED, FEATURE_UDP, PROTOCOL_VERSION, STATUS_ERR,
    STATUS_OK,
};
use hydr_transport::{quic, ws, DynStream, ServerEvent, Tunnel, TunnelHandle};
use tokio::sync::Mutex;

mod udp;

pub use udp::UdpManager;

const DEFAULT_MAX_CONNS: usize = 1024;
/// Окно и лимит попыток аутентификации на один IP (анти-брутфорс).
const AUTH_WINDOW: Duration = Duration::from_secs(60);
const AUTH_MAX_PER_IP: usize = 30;
/// Таймаут WS-хендшейка (TLS + WebSocket upgrade + auth).
const WS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

pub struct ServerConfig {
    pub password: String,
    pub cc_rx: u64,
    pub quic: Option<QuicListen>,
    pub ws: Option<WsListen>,
    pub next_hop: Option<NextHop>,
    /// Максимум одновременных туннелей (0 — значение по умолчанию).
    pub max_conns: usize,
}

#[derive(Clone)]
pub struct QuicListen {
    pub bind: SocketAddr,
    pub server_name: String,
}

#[derive(Clone)]
pub struct WsListen {
    pub bind: SocketAddr,
    pub path: String,
    pub obfuscation: Option<String>,
}

#[derive(Clone)]
pub struct NextHop {
    pub transport: NextHopTransport,
    pub password: String,
}

#[derive(Clone)]
pub enum NextHopTransport {
    Quic {
        addr: SocketAddr,
        server_name: String,
        insecure: bool,
    },
    Ws {
        url: String,
        insecure: bool,
        obfuscation: Option<String>,
    },
}

pub struct Server {
    config: ServerConfig,
    downstream: Mutex<Option<TunnelHandle>>,
    udp: Arc<UdpManager>,
    conn_permits: Arc<tokio::sync::Semaphore>,
    auth_attempts: std::sync::Mutex<HashMap<IpAddr, Vec<Instant>>>,
    /// Кэш использованных client_nonce для защиты от replay атак.
    replay_nonces: std::sync::Mutex<HashSet<Vec<u8>>>,
    conns_active: AtomicU64,
}

/// Максимальный размер кэша nonce; при превышении кэш сбрасывается.
const REPLAY_CACHE_MAX: usize = 8192;

impl Server {
    pub fn new(config: ServerConfig) -> Arc<Self> {
        let max_conns = if config.max_conns == 0 {
            DEFAULT_MAX_CONNS
        } else {
            config.max_conns
        };
        Arc::new(Self {
            config,
            downstream: Mutex::new(None),
            udp: UdpManager::new(),
            conn_permits: Arc::new(tokio::sync::Semaphore::new(max_conns)),
            auth_attempts: std::sync::Mutex::new(HashMap::new()),
            replay_nonces: std::sync::Mutex::new(HashSet::new()),
            conns_active: AtomicU64::new(0),
        })
    }

    fn validate(&self, req: &AuthRequest) -> hydr_core::Result<AuthResponse> {
        if req.version != PROTOCOL_VERSION {
            return Ok(AuthResponse::error_with_code(
                ERR_UNSUPPORTED,
                "unsupported protocol version",
            ));
        }
        if req.client_nonce.len() < 8 {
            return Ok(AuthResponse::error_with_code(
                ERR_PROTOCOL,
                "client nonce too short",
            ));
        }
        let expected = compute_auth_proof(self.config.password.as_bytes(), &req.client_nonce);
        if !ct_eq(&expected, &req.auth_proof) {
            return Ok(AuthResponse::error_with_code(
                ERR_BAD_CREDENTIALS,
                "invalid credentials",
            ));
        }
        if !self.nonce_seen(&req.client_nonce) {
            return Ok(AuthResponse::error_with_code(
                ERR_PROTOCOL,
                "replay detected",
            ));
        }
        Ok(AuthResponse::ok(self.config.cc_rx, FEATURE_UDP))
    }

    /// Отмечает nonce как использованный; возвращает false, если он уже был
    /// (попытка replay) или кэш переполнен и сброшен.
    fn nonce_seen(&self, nonce: &[u8]) -> bool {
        let mut cache = self.replay_nonces.lock().unwrap();
        if cache.contains(nonce) {
            return false;
        }
        cache.insert(nonce.to_vec());
        if cache.len() > REPLAY_CACHE_MAX {
            cache.clear();
        }
        true
    }

    /// Рейт-лимит попыток аутентификации по IP.
    fn rate_allow(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let mut m = self.auth_attempts.lock().unwrap();
        let v = m.entry(ip).or_default();
        v.retain(|t| now.duration_since(*t) < AUTH_WINDOW);
        if v.len() >= AUTH_MAX_PER_IP {
            return false;
        }
        v.push(now);
        true
    }

    /// Снимает/возвращает место под новый туннель.
    fn try_take_conn(&self) -> Option<tokio::sync::OwnedSemaphorePermit> {
        match Arc::clone(&self.conn_permits).try_acquire_owned() {
            Ok(p) => {
                self.conns_active.fetch_add(1, Ordering::Relaxed);
                Some(p)
            }
            Err(_) => None,
        }
    }

    fn release_conn(permit: tokio::sync::OwnedSemaphorePermit, active: &AtomicU64) {
        active.fetch_sub(1, Ordering::Relaxed);
        drop(permit);
    }

    pub async fn run(self: Arc<Self>) -> hydr_core::Result<()> {
        hydr_transport::tls::install_default_provider();

        let mut handles = Vec::new();
        if let Some(q) = &self.config.quic {
            let server = self.clone();
            let q = q.clone();
            handles.push(tokio::spawn(async move {
                server.run_quic(&q).await;
            }));
        }
        if let Some(w) = &self.config.ws {
            let server = self.clone();
            let w = w.clone();
            handles.push(tokio::spawn(async move {
                server.run_ws(&w).await;
            }));
        }
        if handles.is_empty() {
            return Err(hydr_core::Error::InvalidData("no listeners configured"));
        }
        for h in handles {
            let _ = h.await;
        }
        Ok(())
    }

    async fn run_quic(self: Arc<Self>, cfg: &QuicListen) {
        let endpoint = match Self::make_quic_endpoint_with(cfg.bind, &cfg.server_name, self.config.cc_rx) {
            Ok(e) => e,
            Err(e) => {
                tracing::error!("quic listen failed on {}: {e}", cfg.bind);
                return;
            }
        };
        self.run_quic_endpoint(endpoint).await;
    }

    pub fn make_quic_endpoint(
        bind: SocketAddr,
        server_name: &str,
    ) -> Result<quinn::Endpoint, Box<dyn std::error::Error>> {
        Self::make_quic_endpoint_with(bind, server_name, 0)
    }

    pub fn make_quic_endpoint_with(
        bind: SocketAddr,
        server_name: &str,
        cc_rx: u64,
    ) -> Result<quinn::Endpoint, Box<dyn std::error::Error>> {
        let cert = hydr_transport::tls::generate_self_signed(server_name)?;
        let rustls_cfg = hydr_transport::tls::make_server_config(cert.cert_der, cert.key_der)?;
        let quinn_cfg = quic::make_server_config(rustls_cfg, Some(hydr_cc::transport_config(cc_rx)))?;
        Ok(quinn::Endpoint::server(quinn_cfg, bind)?)
    }

    pub async fn run_quic_endpoint(self: Arc<Self>, endpoint: quinn::Endpoint) {
        tracing::info!("QUIC listening on {}", endpoint.local_addr().unwrap());
        loop {
            let incoming = match endpoint.accept().await {
                Some(i) => i,
                None => break,
            };
            let peer = incoming.remote_address();
            if !self.rate_allow(peer.ip()) {
                tracing::warn!("auth rate limit exceeded for {peer}");
                continue;
            }
            let server = self.clone();
            tokio::spawn(async move {
                let conn = match incoming.await {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::debug!("quic handshake failed: {e}");
                        return;
                    }
                };
                let (tunnel, _req) =
                    match quic::server_handshake(conn, |r| server.validate(r)).await {
                        Ok(v) => v,
                        Err(e) => {
                            tracing::debug!("quic auth failed: {e}");
                            return;
                        }
                    };
                server.handle_tunnel(Tunnel::Quic(tunnel)).await;
            });
        }
    }

    async fn run_ws(self: Arc<Self>, cfg: &WsListen) {
        let listener = match Self::make_ws_listener(cfg.bind).await {
            Ok(l) => l,
            Err(e) => {
                tracing::error!("ws listen failed on {}: {e}", cfg.bind);
                return;
            }
        };
        self.run_ws_listener(listener, cfg.path.clone(), cfg.obfuscation.clone())
            .await;
    }

    pub async fn make_ws_listener(
        bind: SocketAddr,
    ) -> std::io::Result<tokio::net::TcpListener> {
        tokio::net::TcpListener::bind(bind).await
    }

    pub async fn run_ws_listener(
        self: Arc<Self>,
        listener: tokio::net::TcpListener,
        path: String,
        obfuscation: Option<String>,
    ) {
        tracing::info!("WS listening on {}", listener.local_addr().unwrap());
        loop {
            let (tcp, peer) = match listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!("ws accept failed: {e}");
                    continue;
                }
            };
            if !self.rate_allow(peer.ip()) {
                tracing::warn!("auth rate limit exceeded for {peer}");
                continue;
            }
            let server = self.clone();
            let path = path.clone();
            let ob = obfuscation
                .clone()
                .map(|k| Arc::new(hydr_core::obfuscation::Obfuscator::new(k.as_bytes())));
            tokio::spawn(async move {
                let val = {
                    let s = server.clone();
                    Arc::new(move |r: &AuthRequest| s.validate(r))
                };
                let handshake = ws::accept_with_obfuscation(tcp, &path, val, ob, false);
                let (tunnel, _req) =
                    match tokio::time::timeout(WS_HANDSHAKE_TIMEOUT, handshake).await {
                        Ok(Ok(v)) => v,
                        Ok(Err(e)) => {
                            tracing::debug!("ws auth failed: {e}");
                            return;
                        }
                        Err(_) => {
                            tracing::debug!("ws handshake timed out");
                            return;
                        }
                    };
                server.handle_tunnel(Tunnel::Ws(tunnel)).await;
            });
        }
    }

    async fn handle_tunnel(self: Arc<Self>, tunnel: Tunnel) {
        let Some(permit) = self.try_take_conn() else {
            tracing::warn!(
                "connection rejected: {} concurrent tunnels",
                self.conns_active.load(Ordering::Relaxed)
            );
            tunnel.close().await;
            return;
        };
        let handle = TunnelHandle::from_tunnel(&tunnel);

        if self.config.next_hop.is_some() {
            let downstream = match self.connect_next_hop().await {
                Ok(t) => t,
                Err(e) => {
                    tracing::error!("next-hop connect failed: {e}");
                    Self::release_conn(permit, &self.conns_active);
                    return;
                }
            };
            let downstream_handle = TunnelHandle::from_tunnel(&downstream);
            *self.downstream.lock().await = Some(downstream_handle);
            let up = handle.clone();
            tokio::spawn(async move {
                let mut downstream = downstream;
                while let Ok(d) = downstream.recv_datagram().await {
                    if up.send_datagram(&d).is_err() {
                        break;
                    }
                }
            });
        }

        let server = self.clone();
        let mut tunnel = tunnel;
        loop {
            let ev = match tunnel.next_event().await {
                Ok(e) => e,
                Err(_) => break,
            };
            match ev {
                ServerEvent::Stream(acc) => {
                    let server = server.clone();
                    tokio::spawn(async move {
                        server.handle_stream(acc).await;
                    });
                }
                ServerEvent::Datagram(dg) => {
                    let server = server.clone();
                    let handle = handle.clone();
                    tokio::spawn(async move {
                        if let Err(e) = server.handle_datagram(&handle, dg).await {
                            tracing::debug!("datagram failed: {e}");
                        }
                    });
                }
            }
        }
        Self::release_conn(permit, &server.conns_active);
    }

    async fn connect_next_hop(&self) -> hydr_core::Result<Tunnel> {
        let hop = self.config.next_hop.as_ref().unwrap();
        let auth = AuthRequest::new_password(hop.password.as_bytes(), 0, FEATURE_UDP);
        match &hop.transport {
            NextHopTransport::Quic {
                addr,
                server_name,
                insecure,
            } => Ok(Tunnel::Quic(
                quic::connect(
                    *addr,
                    server_name,
                    *insecure,
                    Some(quic::default_transport_config()),
                    &auth,
                )
                .await?,
            )),
            NextHopTransport::Ws { url, insecure, obfuscation } => {
                let ob = obfuscation
                    .clone()
                    .map(|k| Arc::new(hydr_core::obfuscation::Obfuscator::new(k.as_bytes())));
                Ok(Tunnel::Ws(
                    ws::connect_with_obfuscation(url, *insecure, &auth, ob).await?,
                ))
            }
        }
    }

    async fn handle_stream(&self, mut acc: hydr_transport::AcceptedStream) {
        let mut peer = match self.connect_peer(&acc).await {
            Ok(p) => p,
            Err(e) => {
                let _ = acc
                    .reply_with_code(STATUS_ERR, ERR_CONNECT_FAILED, e.to_string().as_bytes())
                    .await;
                return;
            }
        };
        if let Err(e) = acc.reply(STATUS_OK, b"").await {
            tracing::debug!("stream ack failed: {e}");
            return;
        }
        let mut relay = acc.into_relay();
        if let Err(e) = bidirectional_copy(&mut relay, &mut peer).await {
            tracing::debug!("relay ended: {e}");
        }
    }

    async fn connect_peer(&self, acc: &hydr_transport::AcceptedStream) -> hydr_core::Result<DynStream> {
        if self.config.next_hop.is_some() {
            let downstream = self
                .downstream
                .lock()
                .await
                .clone()
                .ok_or(hydr_core::Error::InvalidData("no next hop"))?;
            downstream.open_stream(&acc.address).await
        } else {
            let fut = resolve(&acc.address);
            let peer = tokio::time::timeout(Duration::from_secs(10), fut)
                .await
                .map_err(|_| hydr_core::Error::Message("connect timeout".into()))?
                .map_err(|e| hydr_core::Error::Message(format!("connect: {e}")))?;
            Ok(Box::new(peer))
        }
    }

    async fn handle_datagram(
        &self,
        upstream: &TunnelHandle,
        dg: Datagram,
    ) -> hydr_core::Result<()> {
        if self.config.next_hop.is_some() {
            let downstream = self
                .downstream
                .lock()
                .await
                .clone()
                .ok_or(hydr_core::Error::InvalidData("no next hop"))?;
            downstream.send_datagram(&dg)
        } else {
            self.udp.forward(upstream, dg).await
        }
    }
}

async fn resolve(addr: &hydr_core::Address) -> std::io::Result<tokio::net::TcpStream> {
    match addr {
        hydr_core::Address::Ip(ip, port) => tokio::net::TcpStream::connect((*ip, *port)).await,
        hydr_core::Address::Domain(host, port) => {
            tokio::net::TcpStream::connect((host.as_str(), *port)).await
        }
    }
}

pub async fn bidirectional_copy(a: &mut DynStream, b: &mut DynStream) -> hydr_core::Result<()> {
    tokio::io::copy_bidirectional(a, b).await?;
    Ok(())
}