//! CLI и конфигурационный файл `hydr-server`.

use std::path::PathBuf;

use clap::Parser;
use serde::Deserialize;

/// hydr-server — серверная часть протокола hydr (QUIC / WebSocket).
#[derive(Parser, Debug)]
#[command(name = "hydr-server", version, about)]
pub struct Args {
    /// Путь к YAML-конфигу
    #[arg(short, long, value_name = "FILE")]
    pub config: PathBuf,

    /// Уровень логирования (error, warn, info, debug, trace)
    #[arg(short, long, default_value = "info")]
    pub log_level: String,
}

#[derive(Debug, Deserialize)]
pub struct ServerFile {
    pub password: String,
    /// Целевая полоса приёма в бит/с (0 — дефолтный congestion control)
    #[serde(default)]
    pub cc_rx: Option<u64>,
    /// Максимум одновременных туннелей (0 — значение по умолчанию 1024)
    #[serde(default)]
    pub max_conns: Option<usize>,
    #[serde(default)]
    pub quic: Option<QuicFile>,
    #[serde(default)]
    pub ws: Option<WsFile>,
    #[serde(default)]
    pub next_hop: Option<NextHopFile>,
}

#[derive(Debug, Deserialize)]
pub struct QuicFile {
    pub bind: String,
    pub server_name: String,
}

#[derive(Debug, Deserialize)]
pub struct WsFile {
    pub bind: String,
    pub path: String,
    #[serde(default)]
    pub obfuscation: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct NextHopFile {
    pub password: String,
    pub transport: HopTransportFile,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum HopTransportFile {
    Quic {
        addr: String,
        server_name: String,
        #[serde(default)]
        insecure: bool,
    },
    Ws {
        url: String,
        #[serde(default)]
        insecure: bool,
        #[serde(default)]
        obfuscation: Option<String>,
    },
}

pub fn load(path: &PathBuf) -> Result<ServerFile, Box<dyn std::error::Error>> {
    let text = std::fs::read_to_string(path)?;
    Ok(serde_yaml::from_str(&text)?)
}