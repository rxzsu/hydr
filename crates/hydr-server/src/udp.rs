use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use hydr_core::message::Datagram;
use hydr_core::{Address, Error, Result};
use tokio::net::UdpSocket;
use tokio::sync::{watch, Mutex};

use crate::TunnelHandle;

const SESSION_TIMEOUT: Duration = Duration::from_secs(120);
const SWEEP_INTERVAL: Duration = Duration::from_secs(30);

struct UdpSession {
    socket: Arc<UdpSocket>,
    done: watch::Sender<bool>,
    last_active: Instant,
}

pub struct UdpManager {
    sessions: Mutex<HashMap<u32, UdpSession>>,
}

impl UdpManager {
    pub fn new() -> Arc<Self> {
        let m = Arc::new(Self {
            sessions: Mutex::new(HashMap::new()),
        });
        let sweep = m.clone();
        tokio::spawn(async move {
            sweep.sweep_loop().await;
        });
        m
    }

    async fn sweep_loop(self: Arc<Self>) {
        let mut tick = tokio::time::interval(SWEEP_INTERVAL);
        tick.tick().await;
        loop {
            tick.tick().await;
            let now = Instant::now();
            let mut sessions = self.sessions.lock().await;
            let stale: Vec<u32> = sessions
                .iter()
                .filter(|(_, s)| now.duration_since(s.last_active) > SESSION_TIMEOUT)
                .map(|(k, _)| *k)
                .collect();
            for id in stale {
                if let Some(s) = sessions.remove(&id) {
                    let _ = s.done.send(true);
                }
            }
        }
    }

    pub async fn forward(&self, upstream: &TunnelHandle, dg: Datagram) -> Result<()> {
        let socket = {
            let mut sessions = self.sessions.lock().await;
            if let Some(s) = sessions.get_mut(&dg.session_id) {
                s.last_active = Instant::now();
                s.socket.clone()
            } else {
                let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
                let done = watch::Sender::new(false);
                let mut done_rx = done.subscribe();
                let s = socket.clone();
                let upstream = upstream.clone();
                let sid = dg.session_id;
                tokio::spawn(async move {
                    let mut buf = [0u8; 65535];
                    loop {
                        tokio::select! {
                            r = s.recv_from(&mut buf) => match r {
                                Ok((n, from)) => {
                                    let out = Datagram::new(
                                        sid,
                                        Address::Ip(from.ip(), from.port()),
                                        buf[..n].to_vec(),
                                    );
                                    if upstream.send_datagram(&out).is_err() {
                                        break;
                                    }
                                }
                                Err(_) => break,
                            },
                            _ = done_rx.changed() => {
                                if *done_rx.borrow() {
                                    break;
                                }
                            }
                        }
                    }
                });
                sessions.insert(
                    dg.session_id,
                    UdpSession {
                        socket: socket.clone(),
                        done,
                        last_active: Instant::now(),
                    },
                );
                socket
            }
        };

        let target = resolve_target(&dg.address).await?;
        socket.send_to(&dg.payload, target).await?;
        Ok(())
    }
}

async fn resolve_target(addr: &Address) -> Result<SocketAddr> {
    match addr {
        Address::Ip(ip, port) => Ok(SocketAddr::new(*ip, *port)),
        Address::Domain(host, port) => {
            let mut it = tokio::net::lookup_host((host.as_str(), *port)).await?;
            it.next().ok_or(Error::InvalidData("no address for domain"))
        }
    }
}