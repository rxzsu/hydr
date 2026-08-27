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
    /// Пароль (или оставьте пустым при использовании `password_file` / `HYDR_PASSWORD`)
    #[serde(default)]
    pub password: Option<String>,
    /// Путь к файлу с паролем (приоритет выше `password`, файл должен быть 0o600)
    #[serde(default)]
    pub password_file: Option<String>,
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

impl ServerFile {
    /// Возвращает пароль с приоритетом: `password_file` > `HYDR_PASSWORD` > `password`.
    /// Проверяет права файла на Unix (должен быть 0o600/0o400).
    pub fn resolve_password(&self) -> Result<String, Box<dyn std::error::Error>> {
        if let Some(p) = &self.password_file {
            let path = PathBuf::from(p);
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                let meta = std::fs::metadata(&path)?;
                let mode = meta.permissions().mode() & 0o777;
                if mode & 0o077 != 0 {
                    return Err(format!(
                        "password_file {p} has overly permissive mode {mode:o} (expected 600 or 400)"
                    )
                    .into());
                }
            }
            let s = std::fs::read_to_string(&path)?;
            let s = s.trim().to_string();
            if s.is_empty() {
                return Err("password_file is empty".into());
            }
            return Ok(s);
        }
        if let Ok(env) = std::env::var("HYDR_PASSWORD") {
            let env = env.trim().to_string();
            if !env.is_empty() {
                return Ok(env);
            }
        }
        self.password
            .as_ref()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                "password not set: use `password`, `password_file` or env HYDR_PASSWORD".into()
            })
    }
}

#[derive(Debug, Deserialize)]
pub struct QuicFile {
    pub bind: String,
    pub server_name: String,
    /// PEM-сертификат (задаётся вместе с key); без пары — ephemeral self-signed
    #[serde(default)]
    pub cert: Option<String>,
    #[serde(default)]
    pub key: Option<String>,
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
        /// SHA-256 fingerprint сертификата следующего узла (hex).
        #[serde(default)]
        fingerprint: Option<String>,
    },
    Ws {
        url: String,
        #[serde(default)]
        insecure: bool,
        #[serde(default)]
        obfuscation: Option<String>,
        #[serde(default)]
        fingerprint: Option<String>,
    },
}

pub fn load(path: &PathBuf) -> Result<ServerFile, Box<dyn std::error::Error>> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if let Ok(meta) = std::fs::metadata(path) {
            let mode = meta.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                tracing::warn!(
                    "config file {} has permissive mode {mode:o} — consider 600 (secrets in file)",
                    path.display()
                );
            }
        }
    }
    let text = std::fs::read_to_string(path)?;
    Ok(serde_yaml::from_str(&text)?)
}
