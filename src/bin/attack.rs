// Attack tests against a running stack (start it with scripts/attack.sh).
// Every attack must FAIL; the two "control" cases must succeed, so an attack
// can't "pass" just because the stack is down.

use std::sync::Arc;
use std::time::Duration;

use mesh_sidecar::{
    load_certs, new_csr, no_resumption_client, parse_reply, renew, spiffe_id, validity, BoxErr,
    CertStore, Enrolled, SpiffeVerifier, CA_ENROLL_ADDR, CA_RENEW_ADDR,
};
use rcgen::string::Ia5String;
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, SanType,
};
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::{PrivateKeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

const INBOUND: &str = "127.0.0.1:9443";
const OUTBOUND: &str = "127.0.0.1:9000";

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("set {name} (run scripts/attack.sh)"))
}

fn roots() -> Arc<RootCertStore> {
    let mut r = RootCertStore::empty();
    for c in load_certs("certs/ca.crt") {
        r.add(c).unwrap();
    }
    Arc::new(r)
}

// Send "ping" and see if it comes back. Any error = refused.
async fn echoes<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(s: &mut S) -> bool {
    let go = async {
        s.write_all(b"ping\n").await?;
        let mut buf = [0u8; 5];
        s.read_exact(&mut buf).await?;
        Ok::<_, std::io::Error>(&buf == b"ping\n")
    };
    matches!(tokio::time::timeout(Duration::from_secs(3), go).await, Ok(Ok(true)))
}

// Talk straight to the inbound sidecar, as payments' caller, with this cert (or none).
async fn call_inbound(me: Option<Enrolled>) -> Result<bool, BoxErr> {
    let inner = WebPkiServerVerifier::builder(roots()).build()?;
    let b = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SpiffeVerifier::new(inner, "spiffe://mesh/payments")));
    let mut config = match me {
        Some(e) => b.with_client_cert_resolver(Arc::new(CertStore::new(e)?)),
        None => b.with_no_client_auth(),
    };
    no_resumption_client(&mut config);

    let tcp = TcpStream::connect(INBOUND).await?;
    let Ok(mut tls) = TlsConnector::from(Arc::new(config))
        .connect(ServerName::try_from("payments")?, tcp)
        .await
    else {
        return Ok(false);
    };
    Ok(echoes(&mut tls).await)
}

// Enrollment with a CSR we control (optionally claiming an identity).
async fn enroll_claiming(token: &str, claim: Option<&str>) -> Result<Enrolled, BoxErr> {
    let (key, csr) = match claim {
        None => new_csr()?,
        Some(id) => {
            let key = KeyPair::generate()?;
            let mut p = CertificateParams::new(vec![])?;
            p.subject_alt_names = vec![SanType::URI(Ia5String::try_from(id.to_string())?)];
            let csr = p.serialize_request(&key)?.pem()?;
            (key, csr)
        }
    };
    let mut sock = TcpStream::connect(CA_ENROLL_ADDR).await?;
    sock.write_all(format!("{token}\n{csr}").as_bytes()).await?;
    sock.shutdown().await?;
    let mut reply = String::new();
    sock.read_to_string(&mut reply).await?;
    parse_reply(&reply, &key)
}

// A cert for "orders" signed by a CA nobody trusts.
fn rogue_cert() -> Result<Enrolled, BoxErr> {
    let ca_key = KeyPair::generate()?;
    let mut ca = CertificateParams::new(vec![])?;
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    let rogue = Issuer::new(ca, ca_key);

    let key = KeyPair::generate()?;
    let mut p = CertificateParams::new(vec![])?;
    p.subject_alt_names = vec![SanType::URI(Ia5String::try_from("spiffe://mesh/orders".to_string())?)];
    p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let cert = p.signed_by(&key, &rogue)?;
    let key = PrivateKeyDer::try_from(key.serialize_der()).map_err(|e| format!("{e}"))?;
    Ok(Enrolled { cert_chain: vec![cert.der().clone()], key })
}

async fn try_renew(me: Enrolled) -> Result<Enrolled, BoxErr> {
    renew(CA_RENEW_ADDR, roots(), Arc::new(CertStore::new(me)?)).await
}

struct Report {
    failed: usize,
}

impl Report {
    fn check(&mut self, name: &str, ok: bool, detail: impl std::fmt::Display) {
        println!("{}  {name}: {detail}", if ok { "PASS" } else { "FAIL" });
        if !ok {
            self.failed += 1;
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), BoxErr> {
    let mut r = Report { failed: 0 };

    // Control: the legit path works (outbound sidecar as orders).
    let mut plain = TcpStream::connect(OUTBOUND).await?;
    r.check("control: legit call via outbound", echoes(&mut plain).await, "orders -> payments works");

    // 1. No client cert.
    let got = call_inbound(None).await?;
    r.check("no client cert", !got, if got { "ACCEPTED" } else { "refused" });

    // 2. Cert from a rogue CA, claiming an allowed identity.
    let got = call_inbound(Some(rogue_cert()?)).await?;
    r.check("rogue CA cert", !got, if got { "ACCEPTED" } else { "refused" });

    // 3. Valid cert from our CA, but not on the allow-list.
    let analytics = enroll_claiming(&env("ANALYTICS_TOKEN"), None).await?;
    let got = call_inbound(Some(analytics)).await?;
    r.check("valid cert, not on allow-list", !got, if got { "ACCEPTED" } else { "denied by policy" });

    // 4. Reusing a token outbound already redeemed.
    match enroll_claiming(&env("USED_TOKEN"), None).await {
        Ok(_) => r.check("reused enrollment token", false, "CA ISSUED a cert"),
        Err(e) => r.check("reused enrollment token", true, e),
    }

    // 5. CSR claiming orders, with a token for analytics.
    match enroll_claiming(&env("LIAR_TOKEN"), Some("spiffe://mesh/orders")).await {
        Ok(e) => {
            let id = spiffe_id(&e.cert_chain[0]).unwrap_or_default();
            r.check("CSR claims another identity", id == "spiffe://mesh/analytics", format!("cert says {id}"));
        }
        Err(e) => r.check("CSR claims another identity", true, format!("refused: {e}")),
    }

    // Control: renewal with a valid cert works and keeps the identity.
    let fresh = enroll_claiming(&env("RENEW_TOKEN"), None).await?;
    match try_renew(fresh).await {
        Ok(e) => {
            let id = spiffe_id(&e.cert_chain[0]).unwrap_or_default();
            r.check("control: valid renewal", id == "spiffe://mesh/orders", format!("renewed as {id}"));
        }
        Err(e) => r.check("control: valid renewal", false, e),
    }

    // 6. Renewal with a cert from a rogue CA.
    match try_renew(rogue_cert()?).await {
        Ok(_) => r.check("rogue CA cert renewal", false, "CA ISSUED a cert"),
        Err(e) => r.check("rogue CA cert renewal", true, e),
    }

    // 7. Renewal with an expired cert: wait it out, then try.
    let old = enroll_claiming(&env("EXPIRE_TOKEN"), None).await?;
    let (_, expires) = validity(&old.cert_chain[0]).ok_or("no validity")?;
    let wait = expires.duration_since(std::time::SystemTime::now()).unwrap_or_default();
    println!("      (waiting {}s for a cert to expire)", wait.as_secs() + 2);
    tokio::time::sleep(wait + Duration::from_secs(2)).await;
    match try_renew(old).await {
        Ok(_) => r.check("expired cert renewal", false, "CA ISSUED a cert"),
        Err(e) => r.check("expired cert renewal", true, e),
    }

    println!();
    if r.failed == 0 {
        println!("all cases behaved as expected");
        Ok(())
    } else {
        Err(format!("{} case(s) FAILED", r.failed).into())
    }
}
