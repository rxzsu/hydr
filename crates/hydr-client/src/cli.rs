//! CLI и конфигурационный файл `hydr-client`.

use std::path::PathBuf;

use clap::Parser;
use serde::Deserialize;

/// hydr-client — клиент протокола hydr с локальным SOCKS5-входом.
#[derive(Parser, Debug)]
#[command(name = "hydr-client", version, about)]
pub struct Args {
    /// Путь к YAML-конфигу
    #[arg(short, long, value_name = "FILE")]
    pub config: PathBuf,

    /// Уровень логирования (error, warn, info, debug, trace)
    #[arg(short, long, default_value = "info")]
    pub log_level: String,
}

#[derive(Debug, Deserialize)]
pub struct ClientFile {
    pub password: String,
    /// Целевая полоса передачи в бит/с (0 — дефолтный congestion control)
    #[serde(default)]
    pub cc_rx: Option<u64>,
    /// Локальный SOCKS5 адрес (например 127.0.0.1:1080)
    pub socks5_bind: String,
    pub transport: TransportFile,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum TransportFile {
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

pub fn load(path: &PathBuf) -> Result<ClientFile, Box<dyn std::error::Error>> {
    let text = std::fs::read_to_string(path)?;
    Ok(serde_yaml::from_str(&text)?)
}