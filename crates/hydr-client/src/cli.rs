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
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub password_file: Option<String>,
    /// Целевая полоса передачи в бит/с (0 — дефолтный congestion control)
    #[serde(default)]
    pub cc_rx: Option<u64>,
    /// Локальный SOCKS5 адрес (например 127.0.0.1:1080)
    pub socks5_bind: String,
    /// SOCKS5 user/pass (RFC 1929). Обязательны при бинде на внешний адрес:
    /// без них прокси открыт для всей сети. Пароль можно задать через
    /// env `HYDR_SOCKS5_PASSWORD` (приоритет над конфигом).
    #[serde(default)]
    pub socks5_username: Option<String>,
    #[serde(default)]
    pub socks5_password: Option<String>,
    pub transport: TransportFile,
}

impl ClientFile {
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

    /// Пароль SOCKS5: env `HYDR_SOCKS5_PASSWORD` приоритетнее конфига.
    /// Возвращает `None`, если username не задан (auth выключен).
    pub fn resolve_socks5_password(&self) -> Option<String> {
        self.socks5_username.as_ref()?;
        if let Ok(env) = std::env::var("HYDR_SOCKS5_PASSWORD") {
            let env = env.trim().to_string();
            if !env.is_empty() {
                return Some(env);
            }
        }
        self.socks5_password.clone()
    }
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum TransportFile {
    Quic {
        addr: String,
        server_name: String,
        #[serde(default)]
        insecure: bool,
        /// SHA-256 fingerprint сертификата сервера (hex, 64 символа);
        /// надёжнее `insecure: true` — защита от MITM без PKI.
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

pub fn load(path: &PathBuf) -> Result<ClientFile, Box<dyn std::error::Error>> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if let Ok(meta) = std::fs::metadata(path) {
            let mode = meta.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                tracing::warn!(
                    "config file {} has permissive mode {mode:o} — consider 600",
                    path.display()
                );
            }
        }
    }
    let text = std::fs::read_to_string(path)?;
    Ok(serde_yaml::from_str(&text)?)
}
