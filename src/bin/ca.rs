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
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

type BoxErr = Box<dyn std::error::Error + Send + Sync>;

// A request bigger than this is not a real CSR.
const MAX_REQUEST: u64 = 16 * 1024;

const CERT_LIFETIME_HOURS: i64 = 4;

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
) -> Result<String, BoxErr> {
    let mut csr = CertificateSigningRequestParams::from_pem(csr_pem)?;
    let now = OffsetDateTime::now_utc();

    let p = &mut csr.params;
    p.not_before = now - TimeDuration::minutes(1); // tolerate small clock skew
    p.not_after = now + TimeDuration::hours(CERT_LIFETIME_HOURS);
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

async fn handle(
    mut sock: TcpStream,
    tokens: Arc<Tokens>,
    issuer: Arc<Issuer<'static, KeyPair>>,
) -> std::io::Result<()> {
    // Request format: line 1 = token, the rest = the CSR. The client
    // closes its sending side when done, which is how we know it's complete.
    let mut raw = Vec::new();
    let read = tokio::time::timeout(
        Duration::from_secs(5),
        (&mut sock).take(MAX_REQUEST).read_to_end(&mut raw),
    )
    .await;
    if !matches!(read, Ok(Ok(_))) {
        return Ok(()); // too slow or broken: drop it
    }

    let text = String::from_utf8_lossy(&raw);
    let Some((token, csr)) = text.split_once('\n') else {
        sock.write_all(b"ERR malformed request\n").await?;
        return Ok(());
    };

    let Some(identity) = tokens.redeem(token.trim()) else {
        sock.write_all(b"ERR invalid token\n").await?;
        return Ok(());
    };

    match sign(&issuer, csr, &identity) {
        Ok(pem) => {
            println!("issued {CERT_LIFETIME_HOURS}h cert for {identity}");
            sock.write_all(format!("OK\n{pem}").as_bytes()).await?;
        }
        Err(e) => {
            eprintln!("signing failed for {identity}: {e}");
            sock.write_all(b"ERR bad csr\n").await?;
        }
    }
    Ok(())
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

    let listener = TcpListener::bind("127.0.0.1:9100").await?;
    println!("CA service on 127.0.0.1:9100");

    loop {
        let (sock, peer) = listener.accept().await?;
        let tokens = tokens.clone();
        let issuer = issuer.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(sock, tokens, issuer).await {
                eprintln!("{peer} error: {e}");
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let pem = sign(&issuer, &csr_pem, "spiffe://mesh/orders").unwrap();
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----"));

        let (_, p) = x509_parser::pem::parse_x509_pem(pem.as_bytes()).unwrap();
        let cert = p.parse_x509().unwrap();
        let san = cert.subject_alternative_name().unwrap().unwrap();
        let uris: Vec<_> = san.value.general_names.iter().collect();
        assert_eq!(uris.len(), 1);
        assert!(format!("{:?}", uris[0]).contains("spiffe://mesh/orders"));
    }
}