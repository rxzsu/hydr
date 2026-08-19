use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::SignatureScheme;
use rcgen::CertifiedKey;

pub fn install_default_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

pub struct GeneratedCert {
    pub cert_der: CertificateDer<'static>,
    pub key_der: PrivateKeyDer<'static>,
}

pub fn generate_self_signed(server_name: &str) -> Result<GeneratedCert, Box<dyn std::error::Error>> {
    install_default_provider();
    let CertifiedKey {
        cert,
        signing_key,
    } = rcgen::generate_simple_self_signed(vec![server_name.to_string()])?;
    Ok(GeneratedCert {
        cert_der: cert.der().clone(),
        key_der: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            signing_key.serialize_der(),
        )),
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

#[derive(Debug)]
struct SkipVerify;

impl rustls::client::danger::ServerCertVerifier for SkipVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

pub fn make_client_config(insecure: bool) -> Arc<rustls::ClientConfig> {
    install_default_provider();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut roots = rustls::RootCertStore::empty();
    if !insecure {
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }
    let builder = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("supported protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    let mut cfg = builder;
    if insecure {
        cfg.dangerous()
            .set_certificate_verifier(Arc::new(SkipVerify));
    }
    Arc::new(cfg)
}