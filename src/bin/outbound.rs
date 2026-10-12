use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, Error, RootCertStore, SignatureScheme,
};
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;
use x509_parser::prelude::*;

// The only identity this outbound sidecar is willing to talk to.
const EXPECTED_PEER: &str = "spiffe://mesh/payments";

fn load_certs(path: &str) -> Vec<CertificateDer<'static>> {
    CertificateDer::pem_file_iter(path)
        .expect("cannot open cert file")
        .map(|c| c.expect("bad cert"))
        .collect()
}

fn load_key(path: &str) -> PrivateKeyDer<'static> {
    PrivateKeyDer::from_pem_file(path).expect("cannot read key")
}

fn spiffe_id(cert: &CertificateDer) -> Option<String> {
    let (_, parsed) = X509Certificate::from_der(cert.as_ref()).ok()?;
    let san = parsed.subject_alternative_name().ok()??;
    for name in &san.value.general_names {
        if let GeneralName::URI(uri) = name {
            return Some(uri.to_string());
        }
    }
    None
}

// Chain check by rustls, name check by us.
#[derive(Debug)]
struct SpiffeVerifier {
    inner: Arc<WebPkiServerVerifier>,
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
            Some(id) if id == EXPECTED_PEER => Ok(ServerCertVerified::assertion()),
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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut roots = RootCertStore::empty();
    for c in load_certs("certs/ca.crt") {
        roots.add(c)?;
    }
    let inner = WebPkiServerVerifier::builder(Arc::new(roots)).build()?;

    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SpiffeVerifier { inner }))
        .with_client_auth_cert(
            load_certs("certs/orders.crt"),
            load_key("certs/orders.key"),
        )?;
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