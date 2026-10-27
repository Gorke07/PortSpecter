use portspecter_domain::{ServiceObservation, TlsObservation};
use rustls::{
    DigitallySignedStruct, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use sha2::{Digest, Sha256};
use std::{
    net::IpAddr,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpSocket, TcpStream},
};

pub mod cameras;
pub mod discovery;
mod local_names;
mod netbios;
pub mod udp;
pub use local_names::{llmnr_name, mdns_name};
pub use netbios::{query_mac, query_node_status};

/// Uses the operating system resolver, including local and VPN DNS configuration.
/// The permit stays with the native call even if its async caller times out.
pub async fn reverse_name(
    ip: IpAddr,
    slots: Arc<tokio::sync::Semaphore>,
    timeout: Duration,
) -> Option<String> {
    tokio::time::timeout(timeout, async move {
        let permit = slots.acquire_owned().await.ok()?;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let name = dns_lookup::lookup_addr(&ip).ok()?;
            let name = name.trim_end_matches('.');
            (!name.is_empty()
                && name.len() <= 253
                && !name.chars().any(|c| c.is_control() || c.is_whitespace())
                && name.parse::<IpAddr>().is_err())
            .then(|| name.to_owned())
        })
        .await
        .ok()
        .flatten()
    })
    .await
    .ok()
    .flatten()
}

pub fn port_hint(port: u16) -> &'static str {
    match port {
        21 => "FTP?",
        22 => "SSH?",
        25 | 465 | 587 => "SMTP?",
        53 => "DNS?",
        80 | 8000 | 8080 | 3000 => "HTTP?",
        443 | 8443 => "HTTPS?",
        135 => "RPC?",
        139 | 445 => "SMB?",
        1433 => "MSSQL?",
        3306 => "MySQL?",
        3389 => "RDP?",
        5432 => "PostgreSQL?",
        5900 => "VNC?",
        6379 => "Redis?",
        _ => "TCP",
    }
}

pub async fn inspect(
    ip: IpAddr,
    port: u16,
    hostname: Option<String>,
    source: Option<IpAddr>,
) -> ServiceObservation {
    let fallback = ServiceObservation {
        name: port_hint(port).into(),
        evidence: "Port-number hint only; protocol not verified".into(),
        tls: None,
    };
    tokio::time::timeout(
        Duration::from_secs(5),
        inspect_inner(ip, port, hostname, source),
    )
    .await
    .unwrap_or(fallback)
}

async fn connect(ip: IpAddr, port: u16, source: Option<IpAddr>) -> std::io::Result<TcpStream> {
    let socket = if ip.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    if let Some(source) = source {
        socket.bind(std::net::SocketAddr::new(source, 0))?;
    }
    socket.connect(std::net::SocketAddr::new(ip, port)).await
}

async fn inspect_inner(
    ip: IpAddr,
    port: u16,
    hostname: Option<String>,
    source: Option<IpAddr>,
) -> ServiceObservation {
    let mut result = ServiceObservation {
        name: port_hint(port).into(),
        evidence: "Port-number hint only; protocol not verified".into(),
        tls: None,
    };
    let Ok(mut stream) = connect(ip, port, source).await else {
        result.evidence = "Service connection failed after port discovery".into();
        return result;
    };
    if matches!(port, 443 | 465 | 636 | 853 | 993 | 995 | 8443) {
        let capture = Arc::new(Mutex::new(None));
        let roots =
            rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(
            Arc::new(roots),
            provider.clone(),
        )
        .build()
        .expect("valid built-in roots");
        let config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("supported TLS")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(CaptureVerifier {
                inner: verifier,
                capture: capture.clone(),
            }))
            .with_no_client_auth();
        let server_name = hostname.as_deref().unwrap_or("").to_string();
        let server_name = if server_name.is_empty() {
            ServerName::from(ip)
        } else {
            match ServerName::try_from(server_name) {
                Ok(v) => v,
                Err(_) => ServerName::from(ip),
            }
        };
        let handshake = tokio_rustls::TlsConnector::from(Arc::new(config))
            .connect(server_name, stream)
            .await;
        let captured = capture.lock().unwrap_or_else(|e| e.into_inner()).clone();
        if let Some((bytes, validation)) = captured
            && let Ok((_, cert)) = x509_parser::parse_x509_certificate(&bytes)
        {
            result.tls = Some(TlsObservation {
                subject: cert.subject().to_string(),
                issuer: cert.issuer().to_string(),
                not_before: cert.validity().not_before.to_string(),
                not_after: cert.validity().not_after.to_string(),
                sha256: format!("{:X}", Sha256::digest(&bytes)),
                validation,
            });
        }
        match handshake {
            Ok(_) => {
                result.name = "TLS".into();
                result.evidence =
                    "TLS handshake completed; certificate validation recorded separately".into();
            }
            Err(e) => {
                result.evidence = format!("TLS inspection: {e}");
                if result.tls.is_some() {
                    result.name = "TLS".into();
                }
            }
        }
        return result;
    }
    if matches!(port, 80 | 8000 | 8080 | 3000 | 9000 | 9090) {
        let authority = hostname.unwrap_or_else(|| {
            if ip.is_ipv6() {
                format!("[{ip}]")
            } else {
                ip.to_string()
            }
        });
        let request = format!(
            "HEAD / HTTP/1.0\r\nHost: {authority}:{port}\r\nUser-Agent: PortSpecter/0.1\r\nConnection: close\r\n\r\n"
        );
        if stream.write_all(request.as_bytes()).await.is_err() {
            return result;
        }
        let mut bytes = vec![0; 16 * 1024];
        if let Ok(n) = stream.read(&mut bytes).await {
            let value = String::from_utf8_lossy(&bytes[..n]);
            if value.starts_with("HTTP/") {
                result.name = "HTTP".into();
                result.evidence = value.lines().take(12).collect::<Vec<_>>().join("\n");
            }
        }
    } else {
        let mut bytes = vec![0; 8192];
        if let Ok(Ok(n)) =
            tokio::time::timeout(Duration::from_millis(500), stream.read(&mut bytes)).await
        {
            let value = String::from_utf8_lossy(&bytes[..n]);
            if n > 0 {
                result.name = if value.starts_with("SSH-") {
                    "SSH"
                } else if value.starts_with("220") {
                    "220 greeting"
                } else {
                    "Banner"
                }
                .into();
                result.evidence = value
                    .chars()
                    .filter(|c| !c.is_control() || matches!(c, '\n' | '\t'))
                    .take(8192)
                    .collect();
            }
        }
    }
    result
}

type CertificateCapture = Arc<Mutex<Option<(Vec<u8>, String)>>>;
#[derive(Debug)]
struct CaptureVerifier {
    inner: Arc<rustls::client::WebPkiServerVerifier>,
    capture: CertificateCapture,
}
impl ServerCertVerifier for CaptureVerifier {
    fn verify_server_cert(
        &self,
        end: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let result = self
            .inner
            .verify_server_cert(end, intermediates, name, ocsp, now);
        let validation = match &result {
            Ok(_) => "trusted".into(),
            Err(e) => format!("untrusted: {e}"),
        };
        *self.capture.lock().unwrap_or_else(|e| e.into_inner()) =
            Some((end.as_ref().to_vec(), validation));
        result
    }
    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(m, c, d)
    }
    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(m, c, d)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn ssh_evidence_comes_from_response_not_port_number() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            stream
                .write_all(b"SSH-2.0-PortSpecterTest\r\n")
                .await
                .unwrap();
        });
        let observed = inspect(address.ip(), address.port(), None, None).await;
        assert_eq!(observed.name, "SSH");
        assert!(observed.evidence.contains("PortSpecterTest"));
        server.await.unwrap();
    }
    #[tokio::test]
    async fn silent_service_has_a_bounded_inspection() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(2)).await;
        });
        let observed = tokio::time::timeout(
            Duration::from_secs(1),
            inspect(address.ip(), address.port(), None, None),
        )
        .await
        .unwrap();
        assert_eq!(observed.name, port_hint(address.port()));
        server.abort();
    }
}
