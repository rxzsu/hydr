use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use hydr_core::message::Datagram;
use hydr_core::{Address, Result};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

use crate::socks5::parse_udp_packet;
use crate::TunnelHandle;

struct RelaySession {
    socket: Arc<UdpSocket>,
    client_addr: Mutex<Option<SocketAddr>>,
}

pub struct UdpRelay {
    tunnel: TunnelHandle,
    sessions: Mutex<HashMap<u32, RelaySession>>,
    next_session: AtomicU32,
}

impl UdpRelay {
    pub fn new(tunnel: TunnelHandle) -> Self {
        Self {
            tunnel,
            sessions: Mutex::new(HashMap::new()),
            next_session: AtomicU32::new(1),
        }
    }

    #[allow(clippy::while_let_loop)]
    pub async fn associate(
        self: &Arc<Self>,
        mut tcp: tokio::net::TcpStream,
        _peer: SocketAddr,
    ) -> Result<()> {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
        let local = socket.local_addr()?;
        let sid = self.next_session.fetch_add(1, Ordering::Relaxed);
        self.sessions
            .lock()
            .await
            .insert(sid, RelaySession { socket, client_addr: Mutex::new(None) });

        let mut resp = vec![5, 0, 0];
        Address::Ip(local.ip(), local.port()).encode(&mut resp);
        tokio::io::AsyncWriteExt::write_all(&mut tcp, &resp)
            .await
            .map_err(hydr_core::Error::Io)?;

        let relay = self.clone();
        let s = relay.sessions.lock().await[&sid].socket.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 65535];
            loop {
                match s.recv_from(&mut buf).await {
                    Ok((n, from)) => {
                        let (target, payload) = match parse_udp_packet(&buf[..n]) {
                            Ok(v) => v,
                            Err(_) => continue,
                        };
                        {
                            let guard = relay.sessions.lock().await;
                            let mut ca = guard[&sid].client_addr.lock().await;
                            if ca.is_none() {
                                *ca = Some(from);
                            }
                        }
                        let dg = Datagram::new(sid, target, payload.to_vec());
                        if relay.tunnel.send_datagram(&dg).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            relay.sessions.lock().await.remove(&sid);
        });

        let _ = tokio::io::copy(&mut tcp, &mut tokio::io::sink()).await;
        Ok(())
    }

    pub async fn route_reply(&self, dg: Datagram) {
        let sessions = self.sessions.lock().await;
        if let Some(s) = sessions.get(&dg.session_id) {
            let client_addr = s.client_addr.lock().await;
            if let Some(addr) = *client_addr {
                let mut pkt = vec![0, 0, 0];
                dg.address.encode(&mut pkt);
                pkt.extend_from_slice(&dg.payload);
                let _ = s.socket.send_to(&pkt, addr).await;
            }
        }
    }
}