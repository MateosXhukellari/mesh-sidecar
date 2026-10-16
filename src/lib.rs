use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use x509_parser::prelude::*;

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