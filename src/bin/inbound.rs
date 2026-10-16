use std::sync::Arc;

use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use serde::Deserialize;
use std::collections::HashSet;
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use mesh_sidecar::{keep_renewed, load_certs, no_resumption_server, spiffe_id, CertStore, CA_ENROLL_ADDR, CA_RENEW_ADDR};

// who many call this service, any other service is denied
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    allow: HashSet<String>,
}

impl Policy {
    fn load(path: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let text = std::fs::read_to_string(path)?;
        Ok(toml::from_str(&text)?)
    }

    fn is_allowed(&self, caller: &str) -> bool {
        self.allow.contains(caller)
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // trust only certs signed from our CA
    let mut roots = RootCertStore::empty();
    for c in load_certs("certs/ca.crt") {
        roots.add(c)?;
    }
    let roots = Arc::new(roots);
    let verifier = WebPkiClientVerifier::builder(roots.clone()).build()?;

    let token = std::env::var("MESH_TOKEN").expect("set MESH_TOKEN");
    let me = mesh_sidecar::enroll(CA_ENROLL_ADDR, &token).await?;

    // The store is asked for a cert on every handshake, so renewal can swap it.
    let store = Arc::new(CertStore::new(me)?);
    tokio::spawn(keep_renewed(CA_RENEW_ADDR, roots, store.clone()));

    let mut config = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_cert_resolver(store);
    no_resumption_server(&mut config);


    let acceptor = TlsAcceptor::from(Arc::new(config));

    let listner = TcpListener::bind("127.0.0.1:9443").await?;
    println!("inbound sidecar (mTLS) on 127.0.0.1:9443 -> backend 127.0.0.1:9001");

    let policy = Arc::new(Policy::load("policy.toml")?);

    loop {
        let (tcp, peer) = listner.accept().await?;
        let acceptor = acceptor.clone();
        let policy = policy.clone();

        tokio::spawn(async move {
            // 1: TLS handshake. Failed if the cert is not signed by our CA
            let mut tls = match acceptor.accept(tcp).await {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("{peer} REJECTED (handshake): {e}");
                    return;
                }
            };

            // Read the verified identity from the caller's certificate
            let caller = {
                let (_, conn) = tls.get_ref();
                conn.peer_certificates()
                    .and_then(|certs| certs.first())
                    .and_then(spiffe_id)
            };

            let Some(caller) = caller else {
                eprintln!("{peer} REJECTED: no identity in cert");
                return;
            };

            // 2: policy
            if !policy.is_allowed(&caller) {
                eprintln!("{peer} DENIED by policy: {caller}");
                return;
            }

            println!("{peer} ALLOWED: {caller}");

            // passed both layers: connect to the real serviceandpipe bytes
            let mut backend = match TcpStream::connect("127.0.0.1:9001").await {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("cannot reach backend: {e}");
                    return;
                }
            };
            let _ = copy_bidirectional(&mut tls, &mut backend).await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_listed_denies_others() {
        let p: Policy = toml::from_str(r#"allow = ["spiffe://mesh/orders"]"#).unwrap();
        assert!(p.is_allowed("spiffe://mesh/orders"));
        assert!(!p.is_allowed("spiffe://mesh/analytics"));
    }

    #[test]
    fn empty_policy_denies_everyone() {
        let p: Policy = toml::from_str("allow = []").unwrap();
        assert!(!p.is_allowed("spiffe://mesh/orders"));
    }

    #[test]
    fn typo_in_policy_is_an_error() {
        assert!(toml::from_str::<Policy>(r#"alow = ["x"]"#).is_err());
    }
}
