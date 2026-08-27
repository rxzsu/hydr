use std::path::Path;
use std::sync::Arc;

use rcgen::CertifiedKey;
use rustls::SignatureScheme;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use sha2::{Digest, Sha256};

pub fn install_default_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

pub struct GeneratedCert {
    pub cert_der: CertificateDer<'static>,
    pub key_der: PrivateKeyDer<'static>,
}

pub fn generate_self_signed(
    server_name: &str,
) -> Result<GeneratedCert, Box<dyn std::error::Error>> {
    install_default_provider();
    let CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec![server_name.to_string()])?;
    Ok(GeneratedCert {
        cert_der: cert.der().clone(),
        key_der: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signing_key.serialize_der())),
    })
}

pub fn make_server_config(
    cert_der: CertificateDer<'static>,
    key_der: PrivateKeyDer<'static>,
) -> Result<rustls::ServerConfig, Box<dyn std::error::Error>> {
    install_default_provider();
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)?;
    Ok(config)
}

/// Загружает сертификат и ключ из PEM-файлов либо генерирует новый self-signed
/// сертификат (и сохраняет его, если пути заданы). Пути фиксируют identity
/// сервера: fingerprint переживает рестарты, клиенты могут пиновать.
pub fn load_or_generate_self_signed(
    server_name: &str,
    cert_path: Option<&Path>,
    key_path: Option<&Path>,
) -> Result<GeneratedCert, Box<dyn std::error::Error>> {
    match (cert_path, key_path) {
        (Some(cp), Some(kp)) => {
            if cp.exists() && kp.exists() {
                return Ok(GeneratedCert {
                    cert_der: CertificateDer::from_pem_file(cp)?,
                    key_der: PrivateKeyDer::from_pem_file(kp)?,
                });
            }
            if !cp.exists() != !kp.exists() {
                return Err("cert and key must either both exist or both be absent".into());
            }
            let cert = generate_self_signed(server_name)?;
            write_pem(cp, "CERTIFICATE", cert.cert_der.as_ref())?;
            write_pem(kp, "PRIVATE KEY", cert.key_der.secret_der())?;
            Ok(cert)
        }
        (None, None) => generate_self_signed(server_name),
        _ => Err("cert and key paths must be set together".into()),
    }
}

fn write_pem(path: &Path, tag: &str, der: &[u8]) -> std::io::Result<()> {
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut pem = format!("-----BEGIN {tag}-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).expect("base64 is ascii"));
        pem.push('\n');
    }
    pem.push_str(&format!("-----END {tag}-----\n"));
    // атомарная запись: tmp + rename, файл 0o600 (приватный ключ)
    let tmp = path.with_extension("tmp");
    {
        use std::io::Write as _;
        let mut f = std::fs::File::create(&tmp)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let _ = f.set_permissions(std::fs::Permissions::from_mode(0o600));
        }
        f.write_all(pem.as_bytes())?;
        f.sync_all()?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
    }
    std::fs::rename(&tmp, path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

/// SHA-256 fingerprint сертификата (DER), нижний регистр hex.
/// Пинуется клиентом вместо полноценной PKI-верификации (self-signed режим).
pub fn cert_fingerprint_hex(cert: &CertificateDer<'_>) -> String {
    fingerprint_hex(&cert_fingerprint(cert))
}

pub fn cert_fingerprint(cert: &CertificateDer<'_>) -> [u8; 32] {
    Sha256::digest(cert.as_ref()).into()
}

/// Hex-кодирование готового fingerprint (нижний регистр).
pub fn fingerprint_hex(bytes: &[u8; 32]) -> String {
    hex_encode(bytes)
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Разбирает hex-fingerprint (64 hex-символа, разделители `:` допускаются).
pub fn parse_fingerprint(s: &str) -> Option<[u8; 32]> {
    let clean: String = s.chars().filter(|c| *c != ':').collect();
    if clean.len() != 64 || !clean.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, chunk) in clean.as_bytes().chunks(2).enumerate() {
        out[i] = u8::from_str_radix(std::str::from_utf8(chunk).ok()?, 16).ok()?;
    }
    Some(out)
}

/// Как `parse_fingerprint`, но с человекочитаемой ошибкой для CLI/конфига.
pub fn require_fingerprint(s: Option<&str>) -> hydr_core::Result<Option<[u8; 32]>> {
    match s {
        None => Ok(None),
        Some(s) => parse_fingerprint(s)
            .map(Some)
            .ok_or(hydr_core::Error::InvalidData(
                "invalid certificate fingerprint: expected 64 hex characters",
            )),
    }
}

#[derive(Debug)]
struct CustomVerifier {
    /// `Some(pin)` — принимать только сертификат с этим SHA-256;
    /// `None` — принимать любой (режим insecure).
    pin: Option<[u8; 32]>,
}

impl rustls::client::danger::ServerCertVerifier for CustomVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        match self.pin {
            Some(pin) => {
                if cert_fingerprint(end_entity) == pin {
                    Ok(rustls::client::danger::ServerCertVerified::assertion())
                } else {
                    Err(rustls::Error::General(
                        "certificate fingerprint mismatch".into(),
                    ))
                }
            }
            None => Ok(rustls::client::danger::ServerCertVerified::assertion()),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

pub fn make_client_config(insecure: bool) -> Arc<rustls::ClientConfig> {
    make_client_config_with_pin(insecure, None)
}

/// Конфиг клиента с одной из трёх стратегий верификации сервера:
/// - пин по fingerprint (`pin = Some`) — MITM-защита без PKI;
/// - `insecure` — принять любой сертификат (только для тестов);
/// - иначе — стандартная webpki-верификация.
pub fn make_client_config_with_pin(
    insecure: bool,
    pin: Option<[u8; 32]>,
) -> Arc<rustls::ClientConfig> {
    install_default_provider();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut roots = rustls::RootCertStore::empty();
    if !insecure && pin.is_none() {
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }
    let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .expect("supported protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    let mut cfg = builder;
    if pin.is_some() || insecure {
        cfg.dangerous()
            .set_certificate_verifier(Arc::new(CustomVerifier { pin }));
    }
    Arc::new(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_parse_roundtrip() {
        let fp: [u8; 32] = core::array::from_fn(|i| i as u8);
        let hex = fingerprint_hex(&fp);
        assert_eq!(hex.len(), 64);
        assert_eq!(parse_fingerprint(&hex), Some(fp));
        assert_eq!(
            parse_fingerprint(&hex.to_uppercase()),
            Some(fp),
            "uppercase hex must be accepted"
        );
    }

    #[test]
    fn fingerprint_parse_accepts_colons() {
        let fp: [u8; 32] = core::array::from_fn(|i| (i * 7) as u8);
        let hex = fingerprint_hex(&fp);
        let colonized = hex
            .as_bytes()
            .chunks(2)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect::<Vec<_>>()
            .join(":");
        assert_eq!(parse_fingerprint(&colonized), Some(fp));
    }

    #[test]
    fn fingerprint_parse_rejects_garbage() {
        assert_eq!(parse_fingerprint(""), None);
        assert_eq!(parse_fingerprint("zz"), None);
        assert_eq!(parse_fingerprint(&"a".repeat(63)), None);
        assert_eq!(parse_fingerprint(&"g".repeat(64)), None);
    }

    #[test]
    fn load_or_generate_persists_and_keeps_fingerprint() {
        install_default_provider();
        let dir = std::env::temp_dir().join(format!(
            "hydr-tls-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let cp = dir.join("cert.pem");
        let kp = dir.join("key.pem");

        let g1 = load_or_generate_self_signed("localhost", Some(&cp), Some(&kp)).unwrap();
        assert!(cp.exists() && kp.exists(), "pem files must be written");
        let fp1 = cert_fingerprint(&g1.cert_der);

        let g2 = load_or_generate_self_signed("localhost", Some(&cp), Some(&kp)).unwrap();
        assert_eq!(
            fp1,
            cert_fingerprint(&g2.cert_der),
            "restart must reuse the persisted certificate"
        );

        assert!(
            load_or_generate_self_signed("localhost", Some(&cp), None).is_err(),
            "half-configured paths must be rejected"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
