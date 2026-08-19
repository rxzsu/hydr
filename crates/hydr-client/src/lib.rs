use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use hydr_core::message::{AuthRequest, FEATURE_UDP};
use hydr_transport::{quic, ws, ProxyStream, Tunnel, TunnelHandle};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;

mod socks5;
mod udp_relay;

pub use socks5::{parse_udp_packet, CMD_CONNECT, CMD_UDP_ASSOCIATE};
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
    },
    Ws {
        url: String,
        insecure: bool,
        obfuscation: Option<String>,
    },
}

pub struct Client {
    config: ClientConfig,
    tunnel: Mutex<Tunnel>,
    handle: Arc<tokio::sync::RwLock<TunnelHandle>>,
    udp: Arc<UdpRelay>,
    socks5_bind: SocketAddr,
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
            } => {
                let fut = quic::connect(
                    *addr,
                    server_name,
                    *insecure,
                    Some(hydr_cc::transport_config(config.cc_rx)),
                    &auth,
                );
                Ok(Tunnel::Quic(fut.await?))
            }
            ClientTransport::Ws { url, insecure, obfuscation } => {
                let ob = obfuscation
                    .clone()
                    .map(|k| Arc::new(hydr_core::obfuscation::Obfuscator::new(k.as_bytes())));
                Ok(Tunnel::Ws(ws::connect_with_obfuscation(url, *insecure, &auth, ob).await?))
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
        Ok(())
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
                    tracing::warn!("tunnel closed ({e}), reconnecting in {}ms", backoff.as_millis());
                    tokio::time::sleep(backoff).await;
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
                let handle = self.handle.read().await.clone();
                let mut peer_stream = match handle.open_stream(&req.address).await {
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
            socks5::CMD_UDP_ASSOCIATE => {
                self.udp.associate(tcp, peer).await
            }
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