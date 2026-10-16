use std::sync::Arc;

use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;
use mesh_sidecar::{keep_renewed, load_certs, no_resumption_client, CertStore, SpiffeVerifier, CA_ENROLL_ADDR, CA_RENEW_ADDR};

// The only identity this outbound sidecar is willing to talk to.
const EXPECTED_PEER: &str = "spiffe://mesh/payments";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut roots = RootCertStore::empty();
    for c in load_certs("certs/ca.crt") {
        roots.add(c)?;
    }
    let roots = Arc::new(roots);
    let inner = WebPkiServerVerifier::builder(roots.clone()).build()?;

    let token = std::env::var("MESH_TOKEN").expect("set MESH_TOKEN");
    let me = mesh_sidecar::enroll(CA_ENROLL_ADDR, &token).await?;

    // The store is asked for a cert on every handshake, so renewal can swap it.
    let store = Arc::new(CertStore::new(me)?);
    tokio::spawn(keep_renewed(CA_RENEW_ADDR, roots, store.clone()));

    let mut config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SpiffeVerifier::new(inner, EXPECTED_PEER)))
        .with_client_cert_resolver(store);
    no_resumption_client(&mut config);

    let connector = TlsConnector::from(Arc::new(config));
    let server_name = ServerName::try_from("payments")?.to_owned();

    let listener = TcpListener::bind("127.0.0.1:9000").await?;
    println!("outbound sidecar on 127.0.0.1:9000 -> mTLS -> 127.0.0.1:9443");

    loop {
        let (mut plain, peer) = listener.accept().await?;
        let connector = connector.clone();
        let server_name = server_name.clone();

        tokio::spawn(async move {
            let tcp = match TcpStream::connect("127.0.0.1:9443").await {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("{peer} cannot reach inbound sidecar: {e}");
                    return;
                }
            };

            let mut tls = match connector.connect(server_name, tcp).await {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("{peer} REFUSED (server verification): {e}");
                    return;
                }
            };

            let _ = copy_bidirectional(&mut plain, &mut tls).await;
        });
    }
}

/*
SpiffeVerifier wraps the standard WebPkiServerVerifier. The inner field does the real cryptographic work, and we only add our own name rule on top.
The match in verify_server_cert accepts a success or a “not valid for name” error (that’s the DNS-name check failing, which we expect), and rejects every other error, such as an unknown CA or an expired cert. Any other failure still stops the connection.
id == EXPECTED_PEER is the check that matters. It makes sure we reached payments specifically, not just any service your CA signed.
The two verify_tlsXX_signature methods prove the server holds the private key for its cert. We delegate them untouched, because we never write crypto ourselves.
.dangerous() is rustls’s name for “I’m supplying my own verifier.” It’s a warning label, not a flaw, and it’s why we’re careful to delegate the chain check.
with_client_auth_cert(orders.crt, orders.key) is this sidecar’s passport. It’s what the inbound side reads as spiffe://mesh/orders.
"payments" as the ServerName is just a label that satisfies the API. Our verifier ignores it.
The handler is your original proxy again: accept plain, connect out, wrap in TLS, copy_bidirectional. Only the TLS wrap in the middle is new.
*/
