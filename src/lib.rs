use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::{ResolvesClientCert, Resumption, WebPkiServerVerifier};
use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::server::{ClientHello, NoServerSessionStorage, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{
    CertificateError, ClientConfig, ServerConfig, DigitallySignedStruct, Error, RootCertStore, SignatureScheme,
};
use x509_parser::prelude::*;
use rcgen::{CertificateParams, KeyPair};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

pub type BoxErr = Box<dyn std::error::Error + Send + Sync>;

pub const CA_ENROLL_ADDR: &str = "127.0.0.1:9100";
pub const CA_RENEW_ADDR: &str = "127.0.0.1:9101";
// The CA's own identity on the renewal port.
pub const CA_ID: &str = "spiffe://mesh/ca";

pub struct Enrolled {
    pub cert_chain: Vec<CertificateDer<'static>>,
    pub key: PrivateKeyDer<'static>
}

pub fn load_certs(path: &str)-> Vec<CertificateDer<'static>> {
    CertificateDer::pem_file_iter(path)
    .expect("cannot open cert file")
    .map(|c| c.expect("bad cert"))
    .collect()
}

pub fn load_key(path: &str) -> PrivateKeyDer<'static> {
    PrivateKeyDer::from_pem_file(path).expect("cannot read key")
}

// pull the spiffe:// identity of verified cert
pub fn spiffe_id(cert: &CertificateDer) -> Option<String> {
    let (_, parsed) = X509Certificate::from_der(cert.as_ref()).ok()?;
    let san = parsed.subject_alternative_name().ok()??;
    for name in &san.value.general_names {
        if let GeneralName::URI(uri) = name {
            return Some(uri.to_string());
        }
    }
    None
}

// generate a key in mem, ask the CA to sign it and return cert + key
// the private key never leaves the process

pub async fn enroll(
    ca_addr: &str,
    token: &str,
) -> Result<Enrolled, BoxErr> {
    let (key_pair, csr_pem) = new_csr()?;

    let mut sock = TcpStream::connect(ca_addr).await?;
    sock.write_all(format!("{token}\n{csr_pem}").as_bytes()).await?;
    sock.shutdown().await?; // tells the CA the request is complete

    let mut reply = String::new();
    sock.read_to_string(&mut reply).await?;
    parse_reply(&reply, &key_pair)
}

// Fresh key + CSR. The CSR carries no names: the CA decides the identity.
pub fn new_csr() -> Result<(KeyPair, String), BoxErr> {
    let key_pair = KeyPair::generate()?;
    let csr_pem = CertificateParams::new(vec![])?
        .serialize_request(&key_pair)?
        .pem()?;
    Ok((key_pair, csr_pem))
}

// "OK\n<cert pem>" -> cert + the key we generated. Anything else is a refusal.
pub fn parse_reply(reply: &str, key_pair: &KeyPair) -> Result<Enrolled, BoxErr> {
    let Some(pem) = reply.strip_prefix("OK\n") else {
        return Err(format!("CA refused: {}", reply.trim()).into());
    };

    let cert_chain: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(pem.as_bytes())
        .collect::<Result<_, _>>()?;
    if cert_chain.is_empty() {
        return Err("CA sent no certificate".into());
    }
    let key = PrivateKeyDer::try_from(key_pair.serialize_der())
        .map_err(|e| format!("bad key: {e}"))?;

    Ok(Enrolled { cert_chain, key })
}

// Ask the CA for a new cert for the SAME identity, proving who we are with
// the cert currently in `store` (mTLS). A fresh key is generated every time.
pub async fn renew(
    ca_addr: &str,
    roots: Arc<RootCertStore>,
    store: Arc<CertStore>,
) -> Result<Enrolled, BoxErr> {
    let inner = WebPkiServerVerifier::builder(roots).build()?;
    let mut config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SpiffeVerifier::new(inner, CA_ID)))
        .with_client_cert_resolver(store);
    no_resumption_client(&mut config);
    let connector = TlsConnector::from(Arc::new(config));

    let (key_pair, csr_pem) = new_csr()?;

    let talk = async {
        let tcp = TcpStream::connect(ca_addr).await?;
        let mut tls = connector.connect(ServerName::try_from("ca")?, tcp).await?;
        tls.write_all(csr_pem.as_bytes()).await?;
        tls.shutdown().await?; // request complete
        let mut reply = String::new();
        tls.read_to_string(&mut reply).await?;
        Ok::<_, BoxErr>(reply)
    };
    let reply = tokio::time::timeout(Duration::from_secs(10), talk)
        .await
        .map_err(|_| "renewal timed out")??;

    parse_reply(&reply, &key_pair)
}

// TLS session resumption skips certificate checks, so a peer whose cert has
// expired could keep resuming. Turn it off: every connection is a full handshake.
pub fn no_resumption_server(config: &mut ServerConfig) {
    config.session_storage = Arc::new(NoServerSessionStorage {});
    config.send_tls13_tickets = 0;
}

pub fn no_resumption_client(config: &mut ClientConfig) {
    config.resumption = Resumption::disabled();
}

// Holds the cert this sidecar currently presents. rustls asks it for a cert
// at the start of every handshake, so swapping the contents only affects NEW
// connections; existing ones keep the cert they started with.
#[derive(Debug)]
pub struct CertStore {
    current: RwLock<Arc<CertifiedKey>>,
}

impl CertStore {
    pub fn new(e: Enrolled) -> Result<Self, BoxErr> {
        Ok(CertStore { current: RwLock::new(Arc::new(to_certified(e)?)) })
    }

    pub fn set(&self, e: Enrolled) -> Result<(), BoxErr> {
        let ck = Arc::new(to_certified(e)?); // build first, so a bad cert never replaces a good one
        *self.current.write().unwrap() = ck;
        Ok(())
    }

    pub fn leaf(&self) -> CertificateDer<'static> {
        self.current.read().unwrap().cert[0].clone()
    }

    fn get(&self) -> Arc<CertifiedKey> {
        self.current.read().unwrap().clone()
    }
}

fn to_certified(e: Enrolled) -> Result<CertifiedKey, BoxErr> {
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    Ok(CertifiedKey::from_der(e.cert_chain, e.key, &provider)?)
}

impl ResolvesServerCert for CertStore {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.get())
    }
}

impl ResolvesClientCert for CertStore {
    fn resolve(&self, _hints: &[&[u8]], _schemes: &[SignatureScheme]) -> Option<Arc<CertifiedKey>> {
        Some(self.get())
    }

    fn has_certs(&self) -> bool {
        true
    }
}

// (not_before, not_after) of a cert, as SystemTime.
pub fn validity(cert: &CertificateDer) -> Option<(SystemTime, SystemTime)> {
    let (_, parsed) = X509Certificate::from_der(cert.as_ref()).ok()?;
    let v = parsed.validity();
    let t = |ts: i64| Some(UNIX_EPOCH + Duration::from_secs(u64::try_from(ts).ok()?));
    Some((t(v.not_before.timestamp())?, t(v.not_after.timestamp())?))
}

// Renew at 2/3 of the way through the cert's lifetime.
pub fn renew_at(cert: &CertificateDer) -> Option<SystemTime> {
    let (nb, na) = validity(cert)?;
    Some(nb + na.duration_since(nb).ok()? * 2 / 3)
}

// Background task: keep `store` holding a fresh cert, forever.
// On failure: log, back off, retry. The old cert keeps serving meanwhile.
pub async fn keep_renewed(ca_addr: &'static str, roots: Arc<RootCertStore>, store: Arc<CertStore>) {
    loop {
        let leaf = store.leaf();
        let (Some(at), Some((_, expires))) = (renew_at(&leaf), validity(&leaf)) else {
            eprintln!("renewal: cannot read current cert validity, giving up");
            return;
        };
        // At least 1s, so a CA handing out odd certs can't make us spin.
        let wait = at
            .duration_since(SystemTime::now())
            .unwrap_or_default()
            .max(Duration::from_secs(1));
        tokio::time::sleep(wait).await;

        let mut backoff = Duration::from_secs(1);
        loop {
            match renew(ca_addr, roots.clone(), store.clone()).await {
                Ok(new) => {
                    let id = new.cert_chain.first().and_then(spiffe_id);
                    match store.set(new) {
                        Ok(()) => {
                            println!("renewal: new cert for {} installed", id.unwrap_or_default());
                            break;
                        }
                        Err(e) => eprintln!("renewal: CA sent an unusable cert: {e}"),
                    }
                }
                Err(e) => {
                    let note = if SystemTime::now() >= expires { " (current cert EXPIRED)" } else { "" };
                    eprintln!("renewal failed{note}: {e}; retrying in {backoff:?}");
                }
            }
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(Duration::from_secs(30));
        }
    }
}

// Chain check by rustls, name check by us.
#[derive(Debug)]
pub struct SpiffeVerifier {
    inner: Arc<WebPkiServerVerifier>,
    expected: String,
}

impl SpiffeVerifier {
    pub fn new(inner: Arc<WebPkiServerVerifier>, expected: &str) -> Self {
        SpiffeVerifier { inner, expected: expected.to_string() }
    }
}

impl ServerCertVerifier for SpiffeVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        // 1. Normal verification. The chain is checked before the name,
        //    so a "wrong name" error means the chain itself was valid.
        match self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        ) {
            Ok(_) => {}
            Err(Error::InvalidCertificate(CertificateError::NotValidForName)) => {}
            Err(Error::InvalidCertificate(CertificateError::NotValidForNameContext { .. })) => {}
            Err(e) => return Err(e),
        }

        // 2. Our own name check: does the cert carry the identity we expect?
        match spiffe_id(end_entity) {
            Some(id) if id == self.expected => Ok(ServerCertVerified::assertion()),
            _ => Err(Error::General("peer identity mismatch".into())),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}
