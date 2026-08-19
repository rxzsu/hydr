mod cli;

use std::sync::Arc;

use clap::Parser;
use hydr_client::{Client, ClientConfig, ClientTransport};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = cli::Args::parse();
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(args.log_level))
        .init();

    let file = cli::load(&args.config)?;

    let transport = match file.transport {
        cli::TransportFile::Quic {
            addr,
            server_name,
            insecure,
        } => ClientTransport::Quic {
            addr: addr.parse()?,
            server_name,
            insecure,
        },
        cli::TransportFile::Ws {
            url,
            insecure,
            obfuscation,
        } => ClientTransport::Ws {
            url,
            insecure,
            obfuscation,
        },
    };

    let client = Client::connect(ClientConfig {
        transport,
        password: file.password,
        cc_rx: file.cc_rx.unwrap_or(0),
        socks5_bind: file.socks5_bind.parse()?,
    })
    .await?;
    let client = Arc::new(client);

    tokio::spawn(client.clone().serve_datagrams());
    tokio::select! {
        r = client.run_socks5() => r?,
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("shutdown signal received");
        }
    }
    Ok(())
}