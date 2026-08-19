use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use hydr_core::Address;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use hydr_client::{Client, ClientConfig, ClientTransport};
use hydr_server::{Server, ServerConfig};

const PASSWORD: &str = "secret123";

async fn echo_tcp() -> (SocketAddr, tokio::task::JoinHandle<()>) {
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

async fn echo_udp() -> (SocketAddr, tokio::task::JoinHandle<()>) {
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

async fn spawn_quic() -> (Arc<Server>, SocketAddr) {
    let ep = Server::make_quic_endpoint("127.0.0.1:0".parse().unwrap(), "localhost").unwrap();
    let addr = ep.local_addr().unwrap();
    let server = Server::new(ServerConfig {
        password: PASSWORD.into(),
        cc_rx: 0,
        quic: None,
        ws: None,
        next_hop: None,
        max_conns: 0,
    });
    tokio::spawn(server.clone().run_quic_endpoint(ep));
    (server, addr)
}

async fn connect_client(server_quic: SocketAddr, bind: SocketAddr) -> Arc<Client> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let cfg = ClientConfig {
            transport: ClientTransport::Quic {
                addr: server_quic,
                server_name: "localhost".into(),
                insecure: true,
            },
            password: PASSWORD.into(),
            cc_rx: 0,
            socks5_bind: bind,
        };
        match Client::connect(cfg).await {
            Ok(c) => return Arc::new(c),
            Err(_) if Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(e) => panic!("client connect failed: {e}"),
        }
    }
}

async fn socks5_connect(proxy: SocketAddr, target: &Address) -> TcpStream {
    try_socks5_connect(proxy, target).await.expect("socks5 connect")
}

async fn try_socks5_connect(proxy: SocketAddr, target: &Address) -> std::io::Result<TcpStream> {
    let mut s = TcpStream::connect(proxy).await?;
    s.write_all(&[5, 1, 0]).await?;
    let mut resp = [0u8; 2];
    s.read_exact(&mut resp).await?;
    if resp != [5, 0] {
        return Err(std::io::Error::other("no acceptable auth method"));
    }
    let mut req = vec![5, 1, 0];
    target.encode(&mut req);
    s.write_all(&req).await?;
    let mut reply = [0u8; 10];
    s.read_exact(&mut reply).await?;
    if reply[1] != 0 {
        return Err(std::io::Error::other("connect refused"));
    }
    Ok(s)
}

async fn socks5_udp_associate(proxy: SocketAddr) -> (TcpStream, SocketAddr) {
    let mut s = TcpStream::connect(proxy).await.unwrap();
    s.write_all(&[5, 1, 0]).await.unwrap();
    let mut resp = [0u8; 2];
    s.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp, [5, 0]);
    let req = vec![5, 3, 0, 1, 0, 0, 0, 0, 0, 0];
    s.write_all(&req).await.unwrap();
    let mut head = [0u8; 4];
    s.read_exact(&mut head).await.unwrap();
    assert_eq!(head[1], 0, "udp associate succeeded");
    let atyp = head[3];
    let relay = match atyp {
        1 => {
            let mut rest = [0u8; 6];
            s.read_exact(&mut rest).await.unwrap();
            let mut ip = [0u8; 4];
            ip.copy_from_slice(&rest[0..4]);
            let port = u16::from_be_bytes([rest[4], rest[5]]);
            SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::from(ip)), port)
        }
        _ => panic!("unexpected atyp"),
    };
    (s, relay)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn socks5_tcp_end_to_end() {
    let (echo, _eh) = echo_tcp().await;
    let (_server, quic_addr) = spawn_quic().await;

    let client = connect_client(quic_addr, "127.0.0.1:0".parse().unwrap()).await;
    let listener = client.socks5_listener().await.unwrap();
    let socks5_addr = listener.local_addr().unwrap();
    tokio::spawn(client.clone().serve_datagrams());
    tokio::spawn(client.clone().run_socks5_on(listener));

    let target = Address::Ip(echo.ip(), echo.port());
    let mut s = socks5_connect(socks5_addr, &target).await;
    s.write_all(b"hello").await.unwrap();
    let mut buf = [0u8; 5];
    s.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"hello");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn client_reconnects_after_tunnel_close() {
    let (echo, _eh) = echo_tcp().await;
    let (_server, quic_addr) = spawn_quic().await;

    let client = connect_client(quic_addr, "127.0.0.1:0".parse().unwrap()).await;
    let listener = client.socks5_listener().await.unwrap();
    let socks5_addr = listener.local_addr().unwrap();
    tokio::spawn(client.clone().serve_datagrams());
    tokio::spawn(client.clone().run_socks5_on(listener));

    let target = Address::Ip(echo.ip(), echo.port());

    async fn round(socks5_addr: SocketAddr, target: &Address, payload: &[u8]) {
        let mut s = socks5_connect(socks5_addr, target).await;
        s.write_all(payload).await.unwrap();
        let mut buf = vec![0u8; payload.len()];
        s.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, payload);
    }

    round(socks5_addr, &target, b"before").await;

    client.force_close().await;

    let deadline = Instant::now() + Duration::from_secs(10);
    let mut reconnected = false;
    while Instant::now() < deadline {
        if let Ok(mut s) = try_socks5_connect(socks5_addr, &target).await {
            s.write_all(b"after").await.unwrap();
            let mut buf = [0u8; 5];
            if s.read_exact(&mut buf).await.is_ok() && &buf == b"after" {
                reconnected = true;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    assert!(reconnected, "клиент должен переподключиться после обрыва");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn socks5_udp_end_to_end() {
    let (echo, _eh) = echo_udp().await;
    let (_server, quic_addr) = spawn_quic().await;

    let client = connect_client(quic_addr, "127.0.0.1:0".parse().unwrap()).await;
    let listener = client.socks5_listener().await.unwrap();
    let socks5_addr = listener.local_addr().unwrap();
    tokio::spawn(client.clone().serve_datagrams());
    tokio::spawn(client.clone().run_socks5_on(listener));

    let (_control, relay_addr) = socks5_udp_associate(socks5_addr).await;

    let relay = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut pkt = vec![0, 0, 0];
    Address::Ip(echo.ip(), echo.port()).encode(&mut pkt);
    pkt.extend_from_slice(b"ping udp");
    relay.send_to(&pkt, relay_addr).await.unwrap();

    let mut buf = [0u8; 65535];
    let (n, _) = tokio::time::timeout(Duration::from_secs(10), relay.recv_from(&mut buf))
        .await
        .expect("udp reply timeout")
        .unwrap();
    let (_, payload) = hydr_client::parse_udp_packet(&buf[..n]).unwrap();
    assert_eq!(payload, b"ping udp");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_socks5_listeners_share_one_tunnel() {
    let (echo, _eh) = echo_tcp().await;
    let (_server, quic_addr) = spawn_quic().await;

    let client = connect_client(quic_addr, "127.0.0.1:0".parse().unwrap()).await;
    let l1 = client.socks5_listener().await.unwrap();
    let a1 = l1.local_addr().unwrap();
    let l2 = client.socks5_listener().await.unwrap();
    let a2 = l2.local_addr().unwrap();
    tokio::spawn(client.clone().serve_datagrams());
    tokio::spawn(client.clone().run_socks5_on(l1));
    tokio::spawn(client.clone().run_socks5_on(l2));

    let target = Address::Ip(echo.ip(), echo.port());
    let mut handles = Vec::new();
    for (i, addr) in [a1, a2].iter().enumerate() {
        let target = target.clone();
        let addr = *addr;
        handles.push(tokio::spawn(async move {
            let mut s = socks5_connect(addr, &target).await;
            let payload = format!("via listener {i}");
            s.write_all(payload.as_bytes()).await.unwrap();
            let mut buf = vec![0u8; payload.len()];
            s.read_exact(&mut buf).await.unwrap();
            assert_eq!(buf, payload.as_bytes());
        }));
    }
    for h in handles {
        tokio::time::timeout(Duration::from_secs(15), h)
            .await
            .expect("socks5 timeout")
            .expect("socks5 ok");
    }
}