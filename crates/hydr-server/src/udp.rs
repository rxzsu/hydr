use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use hydr_core::message::{Datagram, ERR_RATE_LIMITED};
use hydr_core::{Address, Error, Result};
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, watch};

use crate::TunnelHandle;

const SESSION_TIMEOUT: Duration = Duration::from_secs(120);
const SWEEP_INTERVAL: Duration = Duration::from_secs(30);

/// Дефолтный глобальный cap UDP-сессий: каждая сессия — сокет + таска,
/// без лимита один клиент исчерпывает fd/память.
pub const DEFAULT_MAX_UDP_SESSIONS: usize = 4096;
/// Дефолтный cap UDP-сессий на один IP.
pub const DEFAULT_MAX_UDP_SESSIONS_PER_IP: usize = 64;

struct UdpSession {
    socket: Arc<UdpSocket>,
    done: watch::Sender<bool>,
    last_active: Instant,
    owner: IpAddr,
}

/// Ключ сессии — `(owner_ip, session_id)`: `session_id` выбирает клиент,
/// поэтому глобальный ключ только по id позволяет одному клиенту перехватить
/// чужой сокет (подобрать id) или вытеснить чужую сессию.
type SessionKey = (IpAddr, u32);

pub struct UdpManager {
    sessions: Mutex<HashMap<SessionKey, UdpSession>>,
    /// Счётчик сессий на IP для per-IP cap'а (дублирует обход map ради O(1)).
    per_ip: Mutex<HashMap<IpAddr, usize>>,
    max_sessions: usize,
    max_per_ip: usize,
}

impl UdpManager {
    pub fn new() -> Arc<Self> {
        Self::with_limits(DEFAULT_MAX_UDP_SESSIONS, DEFAULT_MAX_UDP_SESSIONS_PER_IP)
    }

    pub fn with_limits(max_sessions: usize, max_per_ip: usize) -> Arc<Self> {
        let m = Arc::new(Self {
            sessions: Mutex::new(HashMap::new()),
            per_ip: Mutex::new(HashMap::new()),
            max_sessions: if max_sessions == 0 {
                DEFAULT_MAX_UDP_SESSIONS
            } else {
                max_sessions
            },
            max_per_ip: if max_per_ip == 0 {
                DEFAULT_MAX_UDP_SESSIONS_PER_IP
            } else {
                max_per_ip
            },
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
            let stale: Vec<SessionKey> = sessions
                .iter()
                .filter(|(_, s)| now.duration_since(s.last_active) > SESSION_TIMEOUT)
                .map(|(k, _)| *k)
                .collect();
            let n = stale.len();
            if n == 0 {
                continue;
            }
            let mut per_ip = self.per_ip.lock().await;
            for key in stale {
                if let Some(s) = sessions.remove(&key) {
                    let _ = s.done.send(true);
                    decrement_per_ip(&mut per_ip, &s.owner);
                    hydr_core::metrics::global()
                        .udp_sessions_current
                        .fetch_sub(1, Ordering::Relaxed);
                }
            }
            tracing::debug!("udp sweep expired {n} sessions");
        }
    }

    async fn remove_session(&self, key: &SessionKey) {
        let mut sessions = self.sessions.lock().await;
        if let Some(s) = sessions.remove(key) {
            let _ = s.done.send(true);
            let mut per_ip = self.per_ip.lock().await;
            decrement_per_ip(&mut per_ip, &s.owner);
            hydr_core::metrics::global()
                .udp_sessions_current
                .fetch_sub(1, Ordering::Relaxed);
        }
    }

    pub fn session_count(&self) -> usize {
        // Best-effort для метрик/healthcheck: try_lock, чтобы не блокировать.
        self.sessions.try_lock().map(|s| s.len()).unwrap_or(0)
    }

    pub async fn forward(
        &self,
        upstream: &TunnelHandle,
        client_ip: IpAddr,
        dg: Datagram,
    ) -> Result<()> {
        let key = (client_ip, dg.session_id);
        let socket = {
            let mut sessions = self.sessions.lock().await;
            if let Some(s) = sessions.get_mut(&key) {
                s.last_active = Instant::now();
                s.socket.clone()
            } else {
                if sessions.len() >= self.max_sessions {
                    hydr_core::metrics::global()
                        .udp_sessions_rejected
                        .fetch_add(1, Ordering::Relaxed);
                    tracing::warn!(
                        "udp session rejected for {client_ip}: global cap {} reached",
                        self.max_sessions
                    );
                    return Err(rate_limited("udp session table full"));
                }
                {
                    let per_ip = self.per_ip.lock().await;
                    if per_ip.get(&client_ip).copied().unwrap_or(0) >= self.max_per_ip {
                        hydr_core::metrics::global()
                            .udp_sessions_rejected
                            .fetch_add(1, Ordering::Relaxed);
                        tracing::warn!(
                            "udp session rejected for {client_ip}: per-ip cap {} reached",
                            self.max_per_ip
                        );
                        return Err(rate_limited("too many udp sessions for this ip"));
                    }
                }
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
                                    hydr_core::metrics::global()
                                        .datagrams_tx
                                        .fetch_add(1, Ordering::Relaxed);
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
                    key,
                    UdpSession {
                        socket: socket.clone(),
                        done,
                        last_active: Instant::now(),
                        owner: client_ip,
                    },
                );
                {
                    let mut per_ip = self.per_ip.lock().await;
                    *per_ip.entry(client_ip).or_default() += 1;
                }
                let m = hydr_core::metrics::global();
                m.udp_sessions_current.fetch_add(1, Ordering::Relaxed);
                m.udp_sessions_created.fetch_add(1, Ordering::Relaxed);
                socket
            }
        };

        let target = resolve_target(&dg.address).await?;
        let send_res = socket.send_to(&dg.payload, target).await;
        if send_res.is_err() {
            // Невалидная цель (закрытый порт/DNS) — сессия-пустышка не нужна.
            self.remove_session(&key).await;
        }
        send_res?;
        Ok(())
    }
}

fn decrement_per_ip(per_ip: &mut HashMap<IpAddr, usize>, ip: &IpAddr) {
    if let Some(n) = per_ip.get_mut(ip) {
        *n = n.saturating_sub(1);
        if *n == 0 {
            per_ip.remove(ip);
        }
    }
}

/// Ошибка с машиночитаемым кодом rate-limited (0x02): клиент и логи видят
/// именно лимит, а не generic internal/connect-failed.
fn rate_limited(msg: &str) -> Error {
    Error::Message(format!("[code {}] {}", ERR_RATE_LIMITED, msg))
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
