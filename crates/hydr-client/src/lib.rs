use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use hydr_core::Address;
use hydr_core::message::{AuthRequest, FEATURE_UDP};
use hydr_transport::{DynStream, ProxyStream, Tunnel, TunnelHandle, quic, ws};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;

mod socks5;
mod udp_relay;

pub use socks5::{CMD_CONNECT, CMD_UDP_ASSOCIATE, parse_udp_packet};
pub use udp_relay::UdpRelay;

pub struct ClientConfig {
    pub transport: ClientTransport,
    pub password: String,
    pub cc_rx: u64,
    pub socks5_bind: SocketAddr,
}

#[derive(Clone)]
pub enum ClientTransport {
    Quic {
        addr: SocketAddr,
        server_name: String,
        insecure: bool,
        /// SHA-256 fingerprint сертификата сервера (hex) — пин вместо PKI.
        fingerprint: Option<String>,
    },
    Ws {
        url: String,
        insecure: bool,
        obfuscation: Option<String>,
        /// SHA-256 fingerprint сертификата TLS-терминатора (hex).
        fingerprint: Option<String>,
    },
}

pub struct Client {
    config: ClientConfig,
    tunnel: Mutex<Tunnel>,
    handle: Arc<tokio::sync::RwLock<TunnelHandle>>,
    udp: Arc<UdpRelay>,
    socks5_bind: SocketAddr,
    /// Сериализует реконнекты: параллельные запросы ждут один и тот же.
    reconnect_lock: tokio::sync::Mutex<()>,
    /// Инкрементируется при каждом успешном реконнекте (дедупликация).
    tunnel_gen: std::sync::atomic::AtomicU64,
}

impl Client {
    pub async fn connect(config: ClientConfig) -> hydr_core::Result<Client> {
        hydr_transport::tls::install_default_provider();
        let tunnel = Self::connect_tunnel(&config).await?;
        let handle = Arc::new(tokio::sync::RwLock::new(TunnelHandle::from_tunnel(&tunnel)));
        let udp = Arc::new(UdpRelay::new(handle.clone()));
        let socks5_bind = config.socks5_bind;
        Ok(Client {
            config,
            tunnel: Mutex::new(tunnel),
            handle,
            udp,
            socks5_bind,
            reconnect_lock: tokio::sync::Mutex::new(()),
            tunnel_gen: std::sync::atomic::AtomicU64::new(0),
        })
    }

    async fn connect_tunnel(config: &ClientConfig) -> hydr_core::Result<Tunnel> {
        hydr_transport::tls::install_default_provider();
        let auth = AuthRequest::new_password(config.password.as_bytes(), config.cc_rx, FEATURE_UDP);
        match &config.transport {
            ClientTransport::Quic {
                addr,
                server_name,
                insecure,
                fingerprint,
            } => {
                let pin = hydr_transport::tls::require_fingerprint(fingerprint.as_deref())?;
                if *insecure && pin.is_some() {
                    tracing::warn!(
                        "both `insecure` and `fingerprint` set; the pin takes precedence"
                    );
                }
                let fut = quic::connect_with_tls(
                    *addr,
                    server_name,
                    *insecure,
                    pin,
                    Some(hydr_cc::transport_config(config.cc_rx)),
                    &auth,
                );
                Ok(Tunnel::Quic(fut.await?))
            }
            ClientTransport::Ws {
                url,
                insecure,
                obfuscation,
                fingerprint,
            } => {
                let pin = hydr_transport::tls::require_fingerprint(fingerprint.as_deref())?;
                if *insecure && pin.is_some() {
                    tracing::warn!(
                        "both `insecure` and `fingerprint` set; the pin takes precedence"
                    );
                }
                let ob = obfuscation
                    .clone()
                    .map(|k| Arc::new(hydr_core::obfuscation::Obfuscator::new(k.as_bytes())));
                Ok(Tunnel::Ws(
                    ws::connect_with_tls(url, *insecure, pin, &auth, ob).await?,
                ))
            }
        }
    }

    /// Пересоздаёт туннель после обрыва и подменяет общий handle.
    async fn reconnect(&self) -> hydr_core::Result<()> {
        tracing::debug!("connecting tunnel");
        let new_tunnel = Self::connect_tunnel(&self.config).await?;
        let mut tunnel = self.tunnel.lock().await;
        *tunnel = new_tunnel;
        let handle = TunnelHandle::from_tunnel(&tunnel);
        drop(tunnel);
        *self.handle.write().await = handle;
        self.tunnel_gen
            .fetch_add(1, std::sync::atomic::Ordering::Release);
        Ok(())
    }

    /// Реконнект с дедупликацией: если другой таск уже переподключился,
    /// пока мы ждали лок, повторно не подключаемся.
    async fn reconnect_sync(&self) -> hydr_core::Result<()> {
        let seen = self.tunnel_gen.load(std::sync::atomic::Ordering::Acquire);
        let _guard = self.reconnect_lock.lock().await;
        if self.tunnel_gen.load(std::sync::atomic::Ordering::Acquire) != seen {
            return Ok(());
        }
        self.reconnect().await
    }

    fn is_transport_error(e: &hydr_core::Error) -> bool {
        matches!(e, hydr_core::Error::StreamClosed | hydr_core::Error::Io(_))
    }

    /// Открывает поток с одним ретраем: транспортный сбой трактуется как смерть
    /// туннеля → реконнект и повтор. Ошибка уровня протокола (`Message`,
    /// например отказ целевого хоста) не ретраится.
    pub async fn open_stream_resilient(&self, addr: &Address) -> hydr_core::Result<DynStream> {
        let handle = self.handle.read().await.clone();
        match handle.open_stream(addr).await {
            Ok(s) => Ok(s),
            Err(e) if Self::is_transport_error(&e) => {
                tracing::debug!("open_stream failed ({e}); reconnecting tunnel and retrying");
                self.reconnect_sync().await?;
                let handle = self.handle.read().await.clone();
                handle.open_stream(addr).await
            }
            Err(e) => Err(e),
        }
    }

    pub async fn tunnel_handle(&self) -> TunnelHandle {
        self.handle.read().await.clone()
    }

    /// Принудительно закрывает текущий туннель; `serve_datagrams` после этого
    /// переподключится автоматически.
    pub async fn force_close(&self) {
        let handle = self.handle.read().await.clone();
        handle.close();
    }

    pub fn udp_relay(&self) -> Arc<UdpRelay> {
        self.udp.clone()
    }

    pub async fn serve_datagrams(self: Arc<Self>) {
        let mut backoff = Duration::from_millis(500);
        loop {
            let recv = {
                let mut t = self.tunnel.lock().await;
                t.recv_datagram().await
            };
            let dg = match recv {
                Ok(d) => d,
                Err(e) => {
                    // jitter 0.8..1.2 чтобы не было thundering herd после рестарта сервера
                    let jittered = {
                        let mut b = [0u8; 1];
                        let _ = getrandom::fill(&mut b);
                        let factor = 0.8 + (b[0] as f64 / 255.0) * 0.4;
                        Duration::from_millis((backoff.as_millis() as f64 * factor) as u64)
                    };
                    tracing::warn!(
                        "tunnel closed ({e}), reconnecting in {}ms (base {}ms)",
                        jittered.as_millis(),
                        backoff.as_millis()
                    );
                    tokio::time::sleep(jittered).await;
                    backoff = (backoff * 2).min(Duration::from_secs(30));
                    match self.reconnect().await {
                        Ok(()) => {
                            backoff = Duration::from_millis(500);
                            continue;
                        }
                        Err(re) => {
                            tracing::error!("reconnect failed: {re}");
                            continue;
                        }
                    }
                }
            };
            self.udp.route_reply(dg).await;
        }
    }

    pub async fn socks5_listener(&self) -> std::io::Result<tokio::net::TcpListener> {
        tokio::net::TcpListener::bind(self.socks5_bind).await
    }

    pub async fn run_socks5_on(self: Arc<Self>, listener: tokio::net::TcpListener) {
        tracing::info!("SOCKS5 listening on {}", listener.local_addr().unwrap());
        loop {
            let (tcp, peer) = match listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!("accept failed: {e}");
                    continue;
                }
            };
            let client = self.clone();
            tokio::spawn(async move {
                if let Err(e) = client.handle_conn(tcp, peer).await {
                    tracing::debug!("socks5 conn ended: {e}");
                }
            });
        }
    }

    pub async fn run_socks5(self: Arc<Self>) -> hydr_core::Result<()> {
        let listener = self.socks5_listener().await?;
        self.run_socks5_on(listener).await;
        Ok(())
    }

    async fn handle_conn(
        self: Arc<Self>,
        mut tcp: tokio::net::TcpStream,
        peer: SocketAddr,
    ) -> hydr_core::Result<()> {
        let mut buf = [0u8; 2];
        tcp.read_exact(&mut buf).await?;
        if buf[0] != 5 {
            return Err(hydr_core::Error::InvalidData("bad socks version"));
        }
        let nmethods = buf[1] as usize;
        let mut methods = vec![0u8; nmethods];
        tcp.read_exact(&mut methods).await?;
        if !methods.contains(&0) {
            tcp.write_all(&[5, 0xff]).await?;
            return Err(hydr_core::Error::InvalidData("no acceptable auth method"));
        }
        tcp.write_all(&[5, 0]).await?;

        let req = socks5::read_request(&mut tcp).await?;
        match req.cmd {
            socks5::CMD_CONNECT => {
                let mut peer_stream = match self.open_stream_resilient(&req.address).await {
                    Ok(s) => s,
                    Err(e) => {
                        let _ = tcp.write_all(&[5, 0x04, 0, 1, 0, 0, 0, 0, 0, 0]).await;
                        return Err(e);
                    }
                };
                tcp.write_all(&[5, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
                let _ = tokio::io::copy_bidirectional(&mut tcp, &mut peer_stream).await;
                Ok(())
            }
            socks5::CMD_UDP_ASSOCIATE => self.udp.associate(tcp, peer).await,
            _ => {
                tcp.write_all(&[5, 0x07, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
                Err(hydr_core::Error::InvalidData("unsupported command"))
            }
        }
    }
}

pub async fn bidirectional_copy(
    a: &mut dyn ProxyStream,
    b: &mut dyn ProxyStream,
) -> hydr_core::Result<()> {
    tokio::io::copy_bidirectional(a, b).await?;
    Ok(())
}
