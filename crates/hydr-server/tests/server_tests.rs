use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use hydr_core::message::{AuthRequest, Datagram, FEATURE_UDP};
use hydr_core::Address;
use hydr_transport::{quic, ws, QuicTunnel};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::task::JoinHandle;

use hydr_server::{NextHop, NextHopTransport, Server, ServerConfig};

const PASSWORD: &str = "secret123";

async fn echo_tcp() -> (SocketAddr, JoinHandle<()>) {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let h = tokio::spawn(async move {
        loop {
            let (c, _) = match l.accept().await {
                Ok(v) => v,
                Err(_) => break,
            };
            tokio::spawn(async move {
                let (mut r, mut w) = tokio::io::split(c);
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    (addr, h)
}

async fn echo_udp() -> (SocketAddr, JoinHandle<()>) {
    let s = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr = s.local_addr().unwrap();
    let s2 = s.clone();
    let h = tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        while let Ok((n, from)) = s2.recv_from(&mut buf).await {
            let _ = s2.send_to(&buf[..n], from).await;
        }
    });
    (addr, h)
}

fn base_config() -> ServerConfig {
    ServerConfig {
        password: PASSWORD.into(),
        cc_rx: 0,
        quic: None,
        ws: None,
        next_hop: None,
    }
}

fn auth() -> AuthRequest {
    AuthRequest::new_password(PASSWORD.as_bytes(), 0, FEATURE_UDP)
}

async fn spawn_quic(cfg: ServerConfig) -> (Arc<Server>, SocketAddr) {
    let ep = Server::make_quic_endpoint("127.0.0.1:0".parse().unwrap(), "localhost").unwrap();
    let addr = ep.local_addr().unwrap();
    let server = Server::new(cfg);
    tokio::spawn(server.clone().run_quic_endpoint(ep));
    (server, addr)
}

async fn spawn_ws(cfg: ServerConfig) -> (Arc<Server>, String) {
    let l = Server::make_ws_listener("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let addr = l.local_addr().unwrap();
    let server = Server::new(cfg);
    tokio::spawn(server.clone().run_ws_listener(l, "/hydr".into(), None));
    (server, format!("ws://{addr}/hydr"))
}

async fn connect_quic(addr: SocketAddr) -> QuicTunnel {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match quic::connect(addr, "localhost", true, None, &auth()).await {
            Ok(t) => return t,
            Err(_) if Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(e) => panic!("quic connect failed: {e}"),
        }
    }
}

async fn connect_ws(url: &str) -> ws::WsTunnel {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match ws::connect(url, true, &auth()).await {
            Ok(t) => return t,
            Err(_) if Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(e) => panic!("ws connect failed: {e}"),
        }
    }
}

async fn echo_via_tunnel(tunnel: &mut hydr_transport::Tunnel, echo: SocketAddr, label: &str) {
    let addr = Address::Ip(echo.ip(), echo.port());
    let mut stream = tokio::time::timeout(Duration::from_secs(10), tunnel.open_stream(&addr))
        .await
        .expect("open_stream timeout")
        .expect("open_stream ok");
    stream.write_all(b"hello").await.unwrap();
    let mut buf = [0u8; 5];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"hello", "{label}");
    stream.shutdown().await.unwrap();
}

async fn echo_udp_via_tunnel(tunnel: &mut hydr_transport::Tunnel, echo: SocketAddr, label: &str) {
    let dg = Datagram::new(42, Address::Ip(echo.ip(), echo.port()), b"ping".to_vec());
    tunnel.send_datagram(&dg).unwrap();
    let reply = tokio::time::timeout(Duration::from_secs(10), tunnel.recv_datagram())
        .await
        .expect("recv timeout")
        .expect("recv ok");
    assert_eq!(reply.payload, b"ping", "{label}");
    assert_eq!(reply.session_id, 42, "{label}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn quic_tcp_stream() {
    let (echo, _eh) = echo_tcp().await;
    let (_server, quic_addr) = spawn_quic(base_config()).await;
    let mut t = hydr_transport::Tunnel::Quic(connect_quic(quic_addr).await);
    echo_via_tunnel(&mut t, echo, "quic-tcp").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ws_tcp_stream() {
    let (echo, _eh) = echo_tcp().await;
    let (_server, url) = spawn_ws(base_config()).await;
    let mut t = hydr_transport::Tunnel::Ws(connect_ws(&url).await);
    echo_via_tunnel(&mut t, echo, "ws-tcp").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn quic_udp_datagram() {
    let (echo, _eh) = echo_udp().await;
    let (_server, quic_addr) = spawn_quic(base_config()).await;
    let mut t = hydr_transport::Tunnel::Quic(connect_quic(quic_addr).await);
    echo_udp_via_tunnel(&mut t, echo, "quic-udp").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ws_udp_datagram() {
    let (echo, _eh) = echo_udp().await;
    let (_server, url) = spawn_ws(base_config()).await;
    let mut t = hydr_transport::Tunnel::Ws(connect_ws(&url).await);
    echo_udp_via_tunnel(&mut t, echo, "ws-udp").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn auth_failure_rejected() {
    let (_server, quic_addr) = spawn_quic(base_config()).await;
    let bad = AuthRequest::new_password(b"wrong", 0, FEATURE_UDP);
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut got_err = false;
    while Instant::now() < deadline {
        if quic::connect(quic_addr, "localhost", true, None, &bad).await.is_err() {
            got_err = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(got_err, "bad password must be rejected");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn many_concurrent_streams_one_tunnel() {
    let (echo, _eh) = echo_tcp().await;
    let (_server, quic_addr) = spawn_quic(base_config()).await;
    let t = hydr_transport::Tunnel::Quic(connect_quic(quic_addr).await);
    let handle = hydr_transport::TunnelHandle::from_tunnel(&t);
    let addr = Address::Ip(echo.ip(), echo.port());

    let mut handles = Vec::new();
    for i in 0..20u32 {
        let h = handle.clone();
        let addr = addr.clone();
        handles.push(tokio::spawn(async move {
            let mut s = h.open_stream(&addr).await.unwrap();
            let payload = format!("msg-{i}");
            s.write_all(payload.as_bytes()).await.unwrap();
            s.shutdown().await.unwrap();
            let mut buf = vec![0u8; payload.len()];
            s.read_exact(&mut buf).await.unwrap();
            assert_eq!(buf, payload.as_bytes(), "stream {i}");
        }));
    }
    for h in handles {
        tokio::time::timeout(Duration::from_secs(15), h)
            .await
            .expect("stream timeout")
            .expect("stream ok");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn multi_hop_quic() {
    let (echo, _eh) = echo_tcp().await;
    let (echo_udp, _uh) = echo_udp().await;

    let (_target, target_addr) = spawn_quic(base_config()).await;
    let mut front_cfg = base_config();
    front_cfg.next_hop = Some(NextHop {
        password: PASSWORD.into(),
        transport: NextHopTransport::Quic {
            addr: target_addr,
            server_name: "localhost".into(),
            insecure: true,
        },
    });
    let (_front, front_addr) = spawn_quic(front_cfg).await;
    let mut t = hydr_transport::Tunnel::Quic(connect_quic(front_addr).await);
    echo_via_tunnel(&mut t, echo, "multi-hop-quic-tcp").await;
    echo_udp_via_tunnel(&mut t, echo_udp, "multi-hop-quic-udp").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn multi_hop_ws() {
    let (echo, _eh) = echo_tcp().await;

    let (_target, target_addr) = spawn_quic(base_config()).await;
    let mut front_cfg = base_config();
    front_cfg.next_hop = Some(NextHop {
        password: PASSWORD.into(),
        transport: NextHopTransport::Quic {
            addr: target_addr,
            server_name: "localhost".into(),
            insecure: true,
        },
    });
    let (_front, url) = spawn_ws(front_cfg).await;
    let mut t = hydr_transport::Tunnel::Ws(connect_ws(&url).await);
    echo_via_tunnel(&mut t, echo, "multi-hop-ws-tcp").await;
}