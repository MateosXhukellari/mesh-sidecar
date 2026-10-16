use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use x509_parser::prelude::*;
use rcgen::{CertificateParams, KeyPair};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

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
) -> Result<Enrolled, Box<dyn std::error::Error + Send + Sync>> {
    let key_pair = KeyPair::generate()?;
    let csr_pem = CertificateParams::new(vec![])?
        .serialize_request(&key_pair)?
        .pem()?;

    let mut sock = TcpStream::connect(ca_addr).await?;
    sock.write_all(format!("{token}\n{csr_pem}").as_bytes()).await?;
    sock.shutdown().await?; // tells the CA the request is complete

    let mut reply = String::new();
    sock.read_to_string(&mut reply).await?;

    let Some(pem) = reply.strip_prefix("OK\n") else {
        return Err(format!("CA refused: {}", reply.trim()).into());
    };

    let cert_chain: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(pem.as_bytes())
        .collect::<Result<_, _>>()?;
    let key = PrivateKeyDer::try_from(key_pair.serialize_der())
        .map_err(|e| format!("bad key: {e}"))?;

    Ok(Enrolled { cert_chain, key })
}