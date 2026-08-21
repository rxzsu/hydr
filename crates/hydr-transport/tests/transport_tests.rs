use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use hydr_core::message::{
    AuthRequest, AuthResponse, Datagram, FEATURE_UDP, STATUS_OK,
};
use hydr_core::Address;
use hydr_transport::{quic, ws, ServerEvent, Tunnel};

fn test_auth() -> AuthRequest {
    AuthRequest::new_password(b"test-password", 0, FEATURE_UDP)
}

type Validator = Arc<dyn Fn(&AuthRequest) -> hydr_core::Result<AuthResponse> + Send + Sync>;

fn validator() -> Validator {
    Arc::new(|req: &AuthRequest| {
        let expected = hydr_core::message::compute_auth_proof(b"test-password", &req.client_nonce);
        if hydr_core::message::ct_eq(&expected, &req.auth_proof) {
            Ok(AuthResponse::ok(0, FEATURE_UDP))
        } else {
            Ok(AuthResponse::error("bad password"))
        }
    })
}

async fn echo_loop(tunnel: &mut Tunnel) {
    loop {
        match tunnel.next_event().await {
            Ok(ServerEvent::Stream(mut acc)) => {
                acc.reply(STATUS_OK, b"").await.unwrap();
                let mut relay = acc.into_relay();
                let mut buf = [0u8; 1024];
                loop {
                    use tokio::io::AsyncReadExt;
                    let n = relay.read(&mut buf).await.unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    use tokio::io::AsyncWriteExt;
                    let _ = relay.write_all(&buf[..n]).await;
                }
            }
            Ok(ServerEvent::Datagram(dg)) => {
                let _ = tunnel.send_datagram(&dg);
            }
            Err(_) => break,
        }
    }
}

async fn spawn_quic_server() -> SocketAddr {
    let cert = hydr_transport::tls::generate_self_signed("localhost").unwrap();
    let server_cfg = hydr_transport::tls::make_server_config(cert.cert_der, cert.key_der).unwrap();
    let quinn_cfg = quic::make_server_config(server_cfg, Some(quic::default_transport_config()))
        .unwrap();
    let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let endpoint = quinn::Endpoint::server(quinn_cfg, bind).unwrap();
    let local = endpoint.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let conn = match endpoint.accept().await {
                Some(c) => match c.await {
                    Ok(c) => c,
                    Err(_) => continue,
                },
                None => break,
            };
            tokio::spawn(async move {
                let (tunnel, _req) = match quic::server_handshake(conn, |r| {
                    validator()(r)
                })
                .await
                {
                    Ok(v) => v,
                    Err(_) => return,
                };
                let mut t: Tunnel = Tunnel::Quic(tunnel);
                echo_loop(&mut t).await;
            });
        }
    });
    local
}

async fn spawn_ws_server() -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (tcp, _) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => break,
            };
            let val = validator();
            tokio::spawn(async move {
                let (tunnel, _req) =
                    match ws::accept(tcp, "/hydr", val).await {
                        Ok(v) => v,
                        Err(_) => return,
                    };
                let mut t: Tunnel = Tunnel::Ws(tunnel);
                echo_loop(&mut t).await;
            });
        }
    });
    local
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn quic_echo_stream() {
    hydr_transport::tls::install_default_provider();
    let addr = spawn_quic_server().await;
    let tunnel = quic::connect(
        addr,
        "localhost",
        true,
        Some(quic::default_transport_config()),
        &test_auth(),
    )
    .await
    .unwrap();
    let addr = Address::Domain("echo.test".into(), 80);
    let mut stream = tunnel.open_stream(&addr).await.unwrap();
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    stream.write_all(b"hello quic").await.unwrap();
    stream.shutdown().await.unwrap();
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.unwrap();
    assert_eq!(buf, b"hello quic");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ws_echo_stream() {
    let addr = spawn_ws_server().await;
    let url = format!("ws://{addr}/hydr");
    let tunnel = ws::connect(&url, false, &test_auth()).await.unwrap();
    let addr = Address::Domain("echo.test".into(), 80);
    let mut stream = tunnel.open_stream(&addr).await.unwrap();
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    stream.write_all(b"hello ws").await.unwrap();
    stream.shutdown().await.unwrap();
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.unwrap();
    assert_eq!(buf, b"hello ws");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn quic_datagram_echo() {
    hydr_transport::tls::install_default_provider();
    let addr = spawn_quic_server().await;
    let tunnel = quic::connect(
        addr,
        "localhost",
        true,
        Some(quic::default_transport_config()),
        &test_auth(),
    )
    .await
    .unwrap();
    let dg = Datagram::new(1, Address::Ip("8.8.8.8".parse().unwrap(), 53), b"ping".to_vec());
    tunnel.send_datagram(&dg).unwrap();
    let echo = tokio::time::timeout(Duration::from_secs(5), tunnel.recv_datagram())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(echo.session_id, 1);
    assert_eq!(echo.payload, b"ping");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ws_datagram_echo() {
    let addr = spawn_ws_server().await;
    let url = format!("ws://{addr}/hydr");
    let mut tunnel = ws::connect(&url, false, &test_auth()).await.unwrap();
    let dg = Datagram::new(1, Address::Ip("8.8.8.8".parse().unwrap(), 53), b"ping".to_vec());
    tunnel.send_datagram(&dg).unwrap();
    let echo = tokio::time::timeout(Duration::from_secs(5), tunnel.recv_datagram())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(echo.session_id, 1);
    assert_eq!(echo.payload, b"ping");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn auth_failure_rejected() {
    hydr_transport::tls::install_default_provider();
    let addr = spawn_quic_server().await;
    let bad = AuthRequest::new_password(b"wrong", 0, 0);
    let res = quic::connect(
        addr,
        "localhost",
        true,
        Some(quic::default_transport_config()),
        &bad,
    )
    .await;
    assert!(res.is_err());
}

async fn spawn_ws_obfuscated(key: Arc<hydr_core::obfuscation::Obfuscator>) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (tcp, _) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => break,
            };
            let val = validator();
            let key = key.clone();
            tokio::spawn(async move {
                let (tunnel, _req) = match ws::accept_with_obfuscation(tcp, "/hydr", val, Some(key)).await {
                    Ok(v) => v,
                    Err(_) => return,
                };
                let mut t: Tunnel = Tunnel::Ws(tunnel);
                echo_loop(&mut t).await;
            });
        }
    });
    local
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ws_echo_obfuscated() {
    let key = Arc::new(hydr_core::obfuscation::Obfuscator::new(b"obfuscation-key"));
    let addr = spawn_ws_obfuscated(key.clone()).await;
    let url = format!("ws://{addr}/hydr");
    let tunnel = ws::connect_with_obfuscation(&url, false, &test_auth(), Some(key))
        .await
        .unwrap();
    let addr = Address::Domain("echo.test".into(), 80);
    let mut stream = tunnel.open_stream(&addr).await.unwrap();
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    stream.write_all(b"secret bytes").await.unwrap();
    stream.shutdown().await.unwrap();
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.unwrap();
    assert_eq!(buf, b"secret bytes");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ws_obfuscation_key_mismatch_rejected() {
    let server_key = Arc::new(hydr_core::obfuscation::Obfuscator::new(b"server-key"));
    let addr = spawn_ws_obfuscated(server_key).await;
    let url = format!("ws://{addr}/hydr");
    let client_key = Arc::new(hydr_core::obfuscation::Obfuscator::new(b"client-key"));
    let res = ws::connect_with_obfuscation(&url, false, &test_auth(), Some(client_key)).await;
    assert!(res.is_err(), "mismatched obfuscation keys must fail");
}

async fn quic_tunnel() -> hydr_transport::Tunnel {
    hydr_transport::tls::install_default_provider();
    let addr = spawn_quic_server().await;
    hydr_transport::Tunnel::Quic(
        quic::connect(addr, "localhost", true, Some(quic::default_transport_config()), &test_auth())
            .await
            .unwrap(),
    )
}

async fn ws_tunnel() -> hydr_transport::Tunnel {
    let addr = spawn_ws_server().await;
    let url = format!("ws://{addr}/hydr");
    hydr_transport::Tunnel::Ws(ws::connect(&url, false, &test_auth()).await.unwrap())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn quic_large_datagram() {
    let mut t = quic_tunnel().await;
    // QUIC-датаграммы ограничены MTU пути (~1200 байт), берём заведомо влезающее
    let payload = vec![0xABu8; 1024];
    let dg = Datagram::new(1, Address::Ip("8.8.8.8".parse().unwrap(), 53), payload.clone());
    t.send_datagram(&dg).unwrap();
    let echo = tokio::time::timeout(Duration::from_secs(5), t.recv_datagram())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(echo.payload, payload);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ws_large_datagram() {
    let mut t = ws_tunnel().await;
    let payload = vec![0xABu8; 4096];
    let dg = Datagram::new(1, Address::Ip("8.8.8.8".parse().unwrap(), 53), payload.clone());
    t.send_datagram(&dg).unwrap();
    let echo = tokio::time::timeout(Duration::from_secs(5), t.recv_datagram())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(echo.payload, payload);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn quic_multiple_datagrams() {
    let mut t = quic_tunnel().await;
    let count = 20u32;
    for i in 0..count {
        let payload = format!("pkt-{i}").into_bytes();
        let dg = Datagram::new(i, Address::Ip("1.1.1.1".parse().unwrap(), 53), payload);
        t.send_datagram(&dg).unwrap();
    }
    let mut got = std::collections::HashSet::new();
    for _ in 0..count {
        let echo = tokio::time::timeout(Duration::from_secs(5), t.recv_datagram())
            .await
            .unwrap()
            .unwrap();
        got.insert(echo.session_id);
    }
    assert_eq!(got.len() as u32, count, "все датаграммы должны вернуться");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ws_multiple_datagrams() {
    let mut t = ws_tunnel().await;
    let count = 20u32;
    for i in 0..count {
        let payload = format!("pkt-{i}").into_bytes();
        let dg = Datagram::new(i, Address::Ip("1.1.1.1".parse().unwrap(), 53), payload);
        t.send_datagram(&dg).unwrap();
    }
    let mut got = std::collections::HashSet::new();
    for _ in 0..count {
        let echo = tokio::time::timeout(Duration::from_secs(5), t.recv_datagram())
            .await
            .unwrap()
            .unwrap();
        got.insert(echo.session_id);
    }
    assert_eq!(got.len() as u32, count, "все датаграммы должны вернуться");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ws_many_concurrent_streams() {
    let t = ws_tunnel().await;
    let handle = hydr_transport::TunnelHandle::from_tunnel(&t);
    let addr = Address::Domain("echo.test".into(), 80);

    let mut handles = Vec::new();
    for i in 0..20u32 {
        let h = handle.clone();
        let addr = addr.clone();
        handles.push(tokio::spawn(async move {
            let mut s = h.open_stream(&addr).await.unwrap();
            let payload = format!("msg-{i}");
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
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