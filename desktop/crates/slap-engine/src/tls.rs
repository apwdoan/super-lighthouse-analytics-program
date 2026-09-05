//! TLS collector: certificate validity, expiry, protocol, cipher.
//!
//! It runs a REAL handshake rather than trusting whatever the HTTP client
//! negotiated, because the two questions a client report must answer are
//! "does it validate" and "when does it expire", and a failed validation is
//! itself a finding. So it handshakes verifying first; if that fails it
//! handshakes again WITHOUT verification, purely to read the certificate it
//! could not trust, so the report can say whether the cert is expired, or
//! for the wrong host, or signed by an unknown CA.
//!
//! Origin-scoped: one certificate serves every page of a host, so this runs
//! once per site. N pages would be N identical results and N handshakes.

use std::sync::Arc;

use slap_core::schema::{obs, Observation, Value};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use x509_parser::prelude::FromDer;

/// Prefer organizationName, then commonName, then organizationalUnit, then
/// whatever else the name carries.
fn first_attr<'a>(
    it: impl Iterator<Item = &'a x509_parser::x509::AttributeTypeAndValue<'a>>,
) -> Option<String> {
    it.filter_map(|a| a.as_str().ok())
        .next()
        .map(|s| s.to_string())
}

fn flatten_name(name: &x509_parser::x509::X509Name) -> String {
    first_attr(name.iter_organization())
        .or_else(|| first_attr(name.iter_common_name()))
        .or_else(|| first_attr(name.iter_organizational_unit()))
        // Last resort: the whole RFC 2253 string.
        .unwrap_or_else(|| name.to_string())
}

/// Days from `now_unix` until the certificate's notAfter, to one decimal.
fn days_to_expiry(not_after_unix: i64, now_unix: i64) -> f64 {
    ((not_after_unix - now_unix) as f64 / 86400.0 * 10.0).round() / 10.0
}

/// Pure: an end-entity certificate (DER) plus the negotiated protocol/cipher
/// to observations. Network-free, so it tests against a committed cert.
pub fn observations_from_cert(
    cert_der: Option<&[u8]>,
    protocol: Option<&str>,
    cipher: Option<&str>,
    valid: bool,
    now_unix: i64,
) -> Vec<Observation> {
    let mut out = vec![obs("tls.valid", Value::Bool(valid)).unwrap()];
    if let Some(p) = protocol {
        out.push(obs("tls.protocol", Value::from(p)).unwrap());
    }
    if let Some(c) = cipher {
        out.push(obs("tls.cipher", Value::from(c)).unwrap());
    }
    let Some(der) = cert_der else { return out };
    let Ok((_, cert)) = x509_parser::certificate::X509Certificate::from_der(der) else {
        return out;
    };
    let issuer = flatten_name(cert.issuer());
    if !issuer.is_empty() {
        out.push(obs("tls.issuer", Value::from(issuer)).unwrap());
    }
    let subject = flatten_name(cert.subject());
    if !subject.is_empty() {
        out.push(obs("tls.subject", Value::from(subject)).unwrap());
    }
    let not_after = cert.validity().not_after.timestamp();
    out.push(
        obs(
            "tls.days_to_expiry",
            Value::Num(days_to_expiry(not_after, now_unix)),
        )
        .unwrap(),
    );
    out
}

/// A verifier that accepts any certificate. Used ONLY for the second,
/// read-the-cert-anyway handshake after real verification already failed;
/// the `tls.valid=false` observation records that it did not validate.
#[derive(Debug)]
struct AcceptAny(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

struct Handshake {
    cert_der: Option<Vec<u8>>,
    protocol: Option<String>,
    cipher: Option<String>,
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    // Installing a process default is idempotent; ignore the "already set"
    // error. reqwest may have installed one already, which is fine.
    let _ = rustls::crypto::ring::default_provider().install_default();
    Arc::new(rustls::crypto::ring::default_provider())
}

async fn handshake(
    host: &str,
    port: u16,
    config: Arc<rustls::ClientConfig>,
    timeout: std::time::Duration,
) -> Result<Handshake, String> {
    let server_name = rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|_| format!("invalid hostname: {host}"))?;
    let connector = TlsConnector::from(config);
    let connect = async {
        let tcp = TcpStream::connect((host, port))
            .await
            .map_err(|e| e.to_string())?;
        let stream = connector
            .connect(server_name, tcp)
            .await
            .map_err(|e| e.to_string())?;
        let (_, conn) = stream.get_ref();
        Ok::<_, String>(Handshake {
            cert_der: conn
                .peer_certificates()
                .and_then(|c| c.first())
                .map(|c| c.as_ref().to_vec()),
            protocol: conn.protocol_version().map(|v| format!("{v:?}")),
            cipher: conn
                .negotiated_cipher_suite()
                .map(|s| format!("{:?}", s.suite())),
        })
    };
    tokio::time::timeout(timeout, connect)
        .await
        .map_err(|_| "handshake timed out".to_string())?
}

/// Probe one origin's TLS. `now_unix` is injected so the pure expiry maths
/// can be tested; production passes the real clock.
pub async fn probe(url: &str, timeout: std::time::Duration, now_unix: i64) -> Vec<Observation> {
    let parsed = match url::Url::parse(url) {
        Ok(u) => u,
        Err(_) => return vec![obs("tls.valid", Value::Bool(false)).unwrap()],
    };
    if parsed.scheme() != "https" {
        return vec![
            obs("tls.error", Value::from("site not served over HTTPS")).unwrap(),
            obs("tls.valid", Value::Bool(false)).unwrap(),
        ];
    }
    let host = parsed.host_str().unwrap_or("").to_string();
    let port = parsed.port().unwrap_or(443);
    let provider = provider();

    // 1. Verifying handshake.
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let verified_config = Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    match handshake(&host, port, verified_config, timeout).await {
        Ok(h) => {
            return observations_from_cert(
                h.cert_der.as_deref(),
                h.protocol.as_deref(),
                h.cipher.as_deref(),
                true,
                now_unix,
            )
        }
        Err(reason)
            if reason.contains("timed out")
                || reason.contains("connect")
                || reason.contains("os error") =>
        {
            return vec![
                obs("tls.valid", Value::Bool(false)).unwrap(),
                obs(
                    "tls.error",
                    Value::from(format!("connection failed: {reason}")),
                )
                .unwrap(),
            ];
        }
        Err(reason) => {
            // 2. Validation failed for a certificate reason. Reconnect
            // without verification to read the cert and say WHY.
            let permissive = Arc::new(
                rustls::ClientConfig::builder()
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(AcceptAny(provider)))
                    .with_no_client_auth(),
            );
            match handshake(&host, port, permissive, timeout).await {
                Ok(h) => {
                    let mut out = observations_from_cert(
                        h.cert_der.as_deref(),
                        h.protocol.as_deref(),
                        h.cipher.as_deref(),
                        false,
                        now_unix,
                    );
                    out.push(obs("tls.error", Value::from(reason)).unwrap());
                    out
                }
                Err(retry) => vec![
                    obs("tls.valid", Value::Bool(false)).unwrap(),
                    obs(
                        "tls.error",
                        Value::from(format!("{reason}; retry failed: {retry}")),
                    )
                    .unwrap(),
                ],
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn values(obs: Vec<Observation>) -> std::collections::HashMap<String, Value> {
        obs.into_iter()
            .map(|o| (o.metric_key.to_string(), o.value()))
            .collect()
    }

    #[test]
    fn expiry_maths_rounds_to_a_tenth_of_a_day() {
        // 10 days minus 6 hours = 9.75 days.
        let now = 1_700_000_000;
        assert_eq!(days_to_expiry(now + 10 * 86400, now), 10.0);
        assert_eq!(days_to_expiry(now + 86400 * 39 / 4, now), 9.8);
        assert_eq!(
            days_to_expiry(now - 5 * 86400, now),
            -5.0,
            "an expired cert reads negative"
        );
    }

    #[test]
    fn a_self_signed_cert_parses_to_issuer_subject_and_expiry() {
        // A committed self-signed cert (CN=slap.test, O=SLAP Test), so the
        // pure path is exercised without a network or a real CA.
        let der = include_bytes!("../fixtures/selfsigned.der");
        // notBefore in the fixture is 2020; pick a now well inside validity.
        let now = 1_700_000_000; // 2023-11-14
        let v = values(observations_from_cert(
            Some(der),
            Some("TLSv1_3"),
            Some("TLS13_AES_128_GCM_SHA256"),
            false,
            now,
        ));
        assert_eq!(v["tls.valid"], Value::Bool(false));
        assert_eq!(v["tls.protocol"], Value::Text("TLSv1_3".into()));
        assert!(v.contains_key("tls.issuer"), "issuer extracted: {v:?}");
        assert!(v.contains_key("tls.days_to_expiry"));
    }

    #[test]
    fn a_plain_http_url_is_not_a_tls_failure_to_connect() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let v = values(rt.block_on(probe(
            "http://example.com/",
            std::time::Duration::from_secs(2),
            1_700_000_000,
        )));
        assert_eq!(v["tls.valid"], Value::Bool(false));
        assert_eq!(
            v["tls.error"],
            Value::Text("site not served over HTTPS".into())
        );
    }
}
