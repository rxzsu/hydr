use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::UdpManager;

/// Минимальный Prometheus `/metrics`-эндпоинт без внешних зависимостей:
/// plain-TCP HTTP/1.0, только `GET /metrics`. Слушает на `metrics_bind`
/// из конфига сервера (рекомендуется 127.0.0.1 + скрейп через ssh/tailscale).
pub async fn serve(bind: SocketAddr, _udp: Arc<UdpManager>) {
    let listener = match tokio::net::TcpListener::bind(bind).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("metrics listen failed on {bind}: {e}");
            return;
        }
    };
    tracing::info!("metrics listening on {bind}");
    loop {
        let (mut tcp, _peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("metrics accept failed: {e}");
                continue;
            }
        };
        // `udp_sessions_current` ведётся инкрементально в UdpManager;
        // здесь только рендерим снимок.
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            // Игнорируем содержимое запроса: любой GET отдаёт метрики.
            let _ = tcp.read(&mut buf).await;
            let body = hydr_core::metrics::global().render_prometheus();
            let head = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: text/plain; version=0.0.4\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                body.len()
            );
            let _ = tcp.write_all(head.as_bytes()).await;
            let _ = tcp.write_all(body.as_bytes()).await;
        });
    }
}
