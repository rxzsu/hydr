mod cli;

use std::sync::Arc;

use clap::Parser;
use hydr_server::{NextHop, NextHopTransport, QuicListen, Server, ServerConfig, WsListen};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = cli::Args::parse();
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(args.log_level))
        .init();

    let file = cli::load(&args.config)?;

    let quic = file
        .quic
        .map(|q| -> Result<QuicListen, Box<dyn std::error::Error>> {
            Ok(QuicListen {
                bind: q.bind.parse()?,
                server_name: q.server_name,
            })
        })
        .transpose()?;
    let ws = file
        .ws
        .map(|w| -> Result<WsListen, Box<dyn std::error::Error>> {
            Ok(WsListen {
                bind: w.bind.parse()?,
                path: w.path,
                obfuscation: w.obfuscation,
            })
        })
        .transpose()?;
    let next_hop = file
        .next_hop
        .map(|n| -> Result<NextHop, Box<dyn std::error::Error>> {
            let transport = match n.transport {
                cli::HopTransportFile::Quic {
                    addr,
                    server_name,
                    insecure,
                } => NextHopTransport::Quic {
                    addr: addr.parse()?,
                    server_name,
                    insecure,
                },
                cli::HopTransportFile::Ws {
                    url,
                    insecure,
                    obfuscation,
                } => NextHopTransport::Ws {
                    url,
                    insecure,
                    obfuscation,
                },
            };
            Ok(NextHop {
                password: n.password,
                transport,
            })
        })
        .transpose()?;

    let config = ServerConfig {
        password: file.password,
        cc_rx: file.cc_rx.unwrap_or(0),
        quic,
        ws,
        next_hop,
        max_conns: file.max_conns.unwrap_or(0),
    };

    if config.quic.is_none() && config.ws.is_none() {
        return Err("конфиг должен содержать quic или ws слушатель".into());
    }

    let server: Arc<Server> = Server::new(config);
    tokio::select! {
        r = server.run() => r?,
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("shutdown signal received");
        }
    }
    Ok(())
}