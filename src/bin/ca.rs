use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rcgen::string::Ia5String;
use rcgen::{
    CertificateParams, CertificateSigningRequestParams, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose, SanType,
};
use serde::Deserialize;
use time::{Duration as TimeDuration, OffsetDateTime};
use mesh_sidecar::{load_certs, no_resumption_server, spiffe_id, BoxErr, CA_ENROLL_ADDR, CA_ID, CA_RENEW_ADDR};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::danger::ClientCertVerifier;
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use x509_parser::certification_request::X509CertificationRequest;
use x509_parser::prelude::{FromDer, X509Certificate};

// A request bigger than this is not a real CSR.
const MAX_REQUEST: u64 = 16 * 1024;

const DEFAULT_TTL_SECS: u64 = 4 * 3600;

// MESH_CERT_TTL_SECS lets you test rotation with e.g. 30s certs.
fn cert_ttl() -> Result<Duration, BoxErr> {
    let secs = match std::env::var("MESH_CERT_TTL_SECS") {
        Ok(v) => v.parse::<u64>().map_err(|_| "MESH_CERT_TTL_SECS must be a number")?,
        Err(_) => DEFAULT_TTL_SECS,
    };
    if secs == 0 {
        return Err("MESH_CERT_TTL_SECS must be > 0".into());
    }
    Ok(Duration::from_secs(secs))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TokenEntry {
    value: String,
    identity: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TokenFile {
    token: Vec<TokenEntry>,
}

// token -> the one identity it may request. Single use.
struct Tokens {
    map: Mutex<HashMap<String, String>>,
}

impl Tokens {
    fn from_toml(text: &str) -> Result<Self, BoxErr> {
        let file: TokenFile = toml::from_str(text)?;
        let map = file
            .token
            .into_iter()
            .map(|t| (t.value, t.identity))
            .collect();
        Ok(Tokens {
            map: Mutex::new(map),
        })
    }

    fn load(path: &str) -> Result<Self, BoxErr> {
        Self::from_toml(&std::fs::read_to_string(path)?)
    }

    // Removing the entry is what makes the token single-use.
    fn redeem(&self, token: &str) -> Option<String> {
        self.map.lock().unwrap().remove(token)
    }
}

// The identity comes ONLY from the redeemed token. Everything else the
// CSR asks for (names, CA flag, extensions) is overwritten.
fn sign(
    issuer: &Issuer<'static, KeyPair>,
    csr_pem: &str,
    identity: &str,
    ttl: Duration,
) -> Result<String, BoxErr> {
    // from_pem also checks the CSR's self-signature (proof it holds the key).
    let mut csr = CertificateSigningRequestParams::from_pem(csr_pem)?;
    let now = OffsetDateTime::now_utc();

    let p = &mut csr.params;
    // Backdate a little to tolerate clock skew, but keep it small next to
    // the TTL, or short-lived certs would look 2/3 used on arrival.
    let skew = (ttl / 10).min(Duration::from_secs(60));
    p.not_before = now - TimeDuration::try_from(skew)?;
    p.not_after = now + TimeDuration::try_from(ttl)?;
    p.is_ca = IsCa::NoCa;
    p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    p.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ClientAuth,
        ExtendedKeyUsagePurpose::ServerAuth,
    ];
    p.subject_alt_names = vec![SanType::URI(Ia5String::try_from(identity.to_string())?)];
    p.custom_extensions.clear();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, identity);
    p.distinguished_name = dn;

    Ok(csr.signed_by(issuer)?.pem())
}

// Renewal: the identity comes ONLY from the peer cert that rustls already
// verified (chain, expiry, ClientAuth). The CSR only supplies the new key,
// and that key must differ from the current one.
fn renew_for(
    issuer: &Issuer<'static, KeyPair>,
    peer: &CertificateDer,
    csr_pem: &str,
    ttl: Duration,
) -> Result<(String, String), BoxErr> {
    let identity = spiffe_id(peer).ok_or("no identity in cert")?;
    if identity == CA_ID {
        return Err("the CA identity cannot be renewed".into());
    }

    let (_, old) = X509Certificate::from_der(peer.as_ref())?;
    let (_, pem) = x509_parser::pem::parse_x509_pem(csr_pem.as_bytes())?;
    let (_, csr) = X509CertificationRequest::from_der(&pem.contents)?;
    if csr.certification_request_info.subject_pki.raw == old.public_key().raw {
        return Err("CSR reuses the current key".into());
    }

    let cert = sign(issuer, csr_pem, &identity, ttl)?;
    Ok((identity, cert))
}

// The mTLS check on the renewal port: a client cert is required and must
// chain to our CA. rustls does all of it, including expiry.
fn client_verifier(ca: Vec<CertificateDer<'static>>) -> Result<Arc<dyn ClientCertVerifier>, BoxErr> {
    let mut roots = RootCertStore::empty();
    for c in ca {
        roots.add(c)?;
    }
    Ok(WebPkiClientVerifier::builder(Arc::new(roots)).build()?)
}

// The CA's own server cert for the renewal port, minted in memory at startup.
// ServerAuth only, so it can't be used as a client cert to renew itself.
fn ca_server_cert(
    issuer: &Issuer<'static, KeyPair>,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), BoxErr> {
    let key = KeyPair::generate()?;
    let mut p = CertificateParams::new(vec![])?;
    let now = OffsetDateTime::now_utc();
    p.not_before = now - TimeDuration::minutes(1);
    p.not_after = now + TimeDuration::days(30);
    p.is_ca = IsCa::NoCa;
    p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    p.subject_alt_names = vec![SanType::URI(Ia5String::try_from(CA_ID.to_string())?)];
    let cert = p.signed_by(&key, issuer)?;
    let key = PrivateKeyDer::try_from(key.serialize_der()).map_err(|e| format!("bad key: {e}"))?;
    Ok((vec![cert.der().clone()], key))
}

// Read the whole request (client closes its write side when done).
async fn read_request<S: AsyncRead + Unpin>(sock: &mut S) -> Option<String> {
    let mut raw = Vec::new();
    let read = tokio::time::timeout(
        Duration::from_secs(5),
        sock.take(MAX_REQUEST).read_to_end(&mut raw),
    )
    .await;
    if !matches!(read, Ok(Ok(_))) {
        return None; // too slow or broken: drop it
    }
    Some(String::from_utf8_lossy(&raw).into_owned())
}

async fn reply<S: AsyncWrite + Unpin>(sock: &mut S, result: Result<String, &str>) -> std::io::Result<()> {
    match result {
        Ok(pem) => sock.write_all(format!("OK\n{pem}").as_bytes()).await?,
        Err(e) => sock.write_all(format!("ERR {e}\n").as_bytes()).await?,
    }
    sock.shutdown().await
}

async fn handle(
    mut sock: TcpStream,
    tokens: Arc<Tokens>,
    issuer: Arc<Issuer<'static, KeyPair>>,
    ttl: Duration,
) -> std::io::Result<()> {
    // Request format: line 1 = token, the rest = the CSR.
    let Some(text) = read_request(&mut sock).await else {
        return Ok(());
    };
    let Some((token, csr)) = text.split_once('\n') else {
        sock.write_all(b"ERR malformed request\n").await?;
        return Ok(());
    };

    let Some(identity) = tokens.redeem(token.trim()) else {
        sock.write_all(b"ERR invalid token\n").await?;
        return Ok(());
    };

    match sign(&issuer, csr, &identity, ttl) {
        Ok(pem) => {
            println!("enroll: issued {}s cert for {identity}", ttl.as_secs());
            sock.write_all(format!("OK\n{pem}").as_bytes()).await?;
        }
        Err(e) => {
            eprintln!("signing failed for {identity}: {e}");
            sock.write_all(b"ERR bad csr\n").await?;
        }
    }
    Ok(())
}

// Renewal port. By the time we read anything, rustls has verified the client
// cert; a missing, expired or wrong-CA cert never gets this far.
async fn handle_renew(
    tcp: TcpStream,
    acceptor: TlsAcceptor,
    issuer: Arc<Issuer<'static, KeyPair>>,
    ttl: Duration,
) -> std::io::Result<()> {
    let mut tls = match tokio::time::timeout(Duration::from_secs(5), acceptor.accept(tcp)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            eprintln!("renew: REJECTED (handshake): {e}");
            return Ok(());
        }
        Err(_) => return Ok(()),
    };
    let Some(peer) = tls.get_ref().1.peer_certificates().and_then(|c| c.first()).cloned() else {
        return reply(&mut tls, Err("no client cert")).await;
    };
    let Some(csr) = read_request(&mut tls).await else {
        return Ok(());
    };

    match renew_for(&issuer, &peer, &csr, ttl) {
        Ok((identity, pem)) => {
            println!("renew: issued {}s cert for {identity}", ttl.as_secs());
            reply(&mut tls, Ok(pem)).await
        }
        Err(e) => {
            eprintln!("renew: refused: {e}");
            reply(&mut tls, Err("renewal refused")).await
        }
    }
}

async fn serve_enroll(tokens: Arc<Tokens>, issuer: Arc<Issuer<'static, KeyPair>>, ttl: Duration) -> Result<(), BoxErr> {
    let listener = TcpListener::bind(CA_ENROLL_ADDR).await?;
    println!("CA enrollment (token) on {CA_ENROLL_ADDR}");
    loop {
        let (sock, peer) = listener.accept().await?;
        let tokens = tokens.clone();
        let issuer = issuer.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(sock, tokens, issuer, ttl).await {
                eprintln!("{peer} error: {e}");
            }
        });
    }
}

async fn serve_renew(acceptor: TlsAcceptor, issuer: Arc<Issuer<'static, KeyPair>>, ttl: Duration) -> Result<(), BoxErr> {
    let listener = TcpListener::bind(CA_RENEW_ADDR).await?;
    println!("CA renewal (mTLS) on {CA_RENEW_ADDR}");
    loop {
        let (tcp, peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let issuer = issuer.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_renew(tcp, acceptor, issuer, ttl).await {
                eprintln!("{peer} error: {e}");
            }
        });
    }
}

#[tokio::main]
async fn main() -> Result<(), BoxErr> {
    // Load the CA key and cert once. A missing file stops startup.
    let ca_key = KeyPair::from_pem(&std::fs::read_to_string("certs/ca.key")?)?;
    let issuer = Arc::new(Issuer::from_ca_cert_pem(
        &std::fs::read_to_string("certs/ca.crt")?,
        ca_key,
    )?);

    let tokens = Arc::new(Tokens::load("tokens.toml")?);
    let ttl = cert_ttl()?;
    println!("issuing {}s certs", ttl.as_secs());

    let (chain, key) = ca_server_cert(&issuer)?;
    let mut config = ServerConfig::builder()
        .with_client_cert_verifier(client_verifier(load_certs("certs/ca.crt"))?)
        .with_single_cert(chain, key)?;
    no_resumption_server(&mut config); // an expired cert must never renew via a resumed session
    let acceptor = TlsAcceptor::from(Arc::new(config));

    // Either listener failing stops the CA.
    tokio::try_join!(
        serve_enroll(tokens, issuer.clone(), ttl),
        serve_renew(acceptor, issuer, ttl),
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use rustls::pki_types::{pem::PemObject, UnixTime};
    use std::time::{SystemTime, UNIX_EPOCH};

    const HOUR: Duration = Duration::from_secs(3600);
    const ORDERS: &str = "spiffe://mesh/orders";

    // A throwaway CA: (issuer, its cert)
    fn test_ca() -> (Issuer<'static, KeyPair>, CertificateDer<'static>) {
        let key = KeyPair::generate().unwrap();
        let mut p = CertificateParams::new(vec![]).unwrap();
        p.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        p.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let cert = p.self_signed(&key).unwrap().der().clone();
        (Issuer::new(p, key), cert)
    }

    // CSR with a fresh key, optionally claiming an identity.
    fn csr(claim: Option<&str>) -> String {
        let key = KeyPair::generate().unwrap();
        let mut p = CertificateParams::new(vec![]).unwrap();
        if let Some(c) = claim {
            p.subject_alt_names = vec![SanType::URI(Ia5String::try_from(c.to_string()).unwrap())];
        }
        p.serialize_request(&key).unwrap().pem().unwrap()
    }

    fn der(pem: &str) -> CertificateDer<'static> {
        CertificateDer::from_pem_slice(pem.as_bytes()).unwrap()
    }

    #[test]
    fn renewal_keeps_identity() {
        let (issuer, _) = test_ca();
        let current = der(&sign(&issuer, &csr(None), ORDERS, HOUR).unwrap());
        let (id, new) = renew_for(&issuer, &current, &csr(None), HOUR).unwrap();
        assert_eq!(id, ORDERS);
        assert_eq!(spiffe_id(&der(&new)).as_deref(), Some(ORDERS));
    }

    #[test]
    fn renewal_ignores_identity_in_csr() {
        let (issuer, _) = test_ca();
        let current = der(&sign(&issuer, &csr(None), ORDERS, HOUR).unwrap());
        let liar = csr(Some("spiffe://mesh/payments"));
        let (_, new) = renew_for(&issuer, &current, &liar, HOUR).unwrap();
        assert_eq!(spiffe_id(&der(&new)).as_deref(), Some(ORDERS));
    }

    #[test]
    fn renewal_refuses_reused_key() {
        let (issuer, _) = test_ca();
        let key = KeyPair::generate().unwrap();
        let csr_pem = CertificateParams::new(vec![]).unwrap().serialize_request(&key).unwrap().pem().unwrap();
        let current = der(&sign(&issuer, &csr_pem, ORDERS, HOUR).unwrap());
        assert!(renew_for(&issuer, &current, &csr_pem, HOUR).is_err());
    }

    #[test]
    fn expired_cert_is_refused_by_renewal_verifier() {
        let (issuer, ca) = test_ca();
        let v = client_verifier(vec![ca]).unwrap();
        let cert = der(&sign(&issuer, &csr(None), ORDERS, Duration::from_secs(60)).unwrap());

        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        // Valid now...
        assert!(v.verify_client_cert(&cert, &[], UnixTime::since_unix_epoch(now)).is_ok());
        // ...refused once it has expired.
        let later = UnixTime::since_unix_epoch(now + HOUR);
        let err = v.verify_client_cert(&cert, &[], later).unwrap_err();
        assert!(matches!(
            err,
            rustls::Error::InvalidCertificate(rustls::CertificateError::Expired)
                | rustls::Error::InvalidCertificate(rustls::CertificateError::ExpiredContext { .. })
        ), "{err:?}");
    }

    // Regression: the clock-skew backdate once made short-lived certs look
    // 2/3 used on arrival, so sidecars renewed in a tight loop.
    #[test]
    fn short_lived_cert_renews_in_the_future() {
        let (issuer, _) = test_ca();
        let cert = der(&sign(&issuer, &csr(None), ORDERS, Duration::from_secs(15)).unwrap());
        assert!(mesh_sidecar::renew_at(&cert).unwrap() > SystemTime::now());
    }

    #[test]
    fn wrong_ca_cert_is_refused_by_renewal_verifier() {
        let (_, our_ca) = test_ca();
        let (rogue, _) = test_ca();
        let v = client_verifier(vec![our_ca]).unwrap();
        let cert = der(&sign(&rogue, &csr(None), ORDERS, HOUR).unwrap());
        assert!(v.verify_client_cert(&cert, &[], UnixTime::now()).is_err());
    }

    const T: &str = r#"
        [[token]]
        value = "abc"
        identity = "spiffe://mesh/orders"
    "#;

    #[test]
    fn token_works_exactly_once() {
        let t = Tokens::from_toml(T).unwrap();
        assert_eq!(t.redeem("abc"), Some("spiffe://mesh/orders".to_string()));
        assert_eq!(t.redeem("abc"), None);
    }

    #[test]
    fn unknown_token_is_refused() {
        let t = Tokens::from_toml(T).unwrap();
        assert_eq!(t.redeem("nope"), None);
    }

    #[test]
    fn identity_comes_from_token_not_csr() {
        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(vec![]).unwrap();
        ca_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let issuer = Issuer::new(ca_params, ca_key);

        // A CSR that *claims* to be payments.
        let key = KeyPair::generate().unwrap();
        let mut req = CertificateParams::new(vec![]).unwrap();
        req.subject_alt_names = vec![SanType::URI(
            Ia5String::try_from("spiffe://mesh/payments".to_string()).unwrap(),
        )];
        let csr_pem = req.serialize_request(&key).unwrap().pem().unwrap();

        // The token says orders.
        let pem = sign(&issuer, &csr_pem, "spiffe://mesh/orders", HOUR).unwrap();
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----"));

        let (_, p) = x509_parser::pem::parse_x509_pem(pem.as_bytes()).unwrap();
        let cert = p.parse_x509().unwrap();
        let san = cert.subject_alternative_name().unwrap().unwrap();
        let uris: Vec<_> = san.value.general_names.iter().collect();
        assert_eq!(uris.len(), 1);
        assert!(format!("{:?}", uris[0]).contains("spiffe://mesh/orders"));
    }
}