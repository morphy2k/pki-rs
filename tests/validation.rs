use std::io;

use pki_rs::certificate::{Certificate, CertificateChainBuilder};
use tracing::Level;

const ROOT_CERT: &[u8] = include_bytes!("examples/root.crt");
const VALID_CERT_CHAIN: &[u8] = include_bytes!("examples/chain-valid.crt");
const INVALID_CERT_CHAIN: &[u8] = include_bytes!("examples/chain-invalid.crt");

fn init() {
    tracing_subscriber::fmt()
        .with_max_level(Level::TRACE)
        .pretty()
        .with_test_writer()
        .try_init()
        .ok();
}

#[test]
fn validate_chain_period() {
    init();

    let mut certificates = read_certs(VALID_CERT_CHAIN);

    let chain = CertificateChainBuilder::default()
        .set_leaf(certificates.pop().unwrap())
        .set_intermediates(certificates)
        .build()
        .unwrap();

    assert!(chain.validate_period().is_ok());
}

#[test]
fn validate_valid_chain() {
    init();

    let trust_anchor = Certificate::from_pem(ROOT_CERT).unwrap();
    let mut certificates = read_certs(VALID_CERT_CHAIN);

    let chain = CertificateChainBuilder::default()
        .set_leaf(certificates.pop().unwrap())
        .set_intermediates(certificates)
        .build()
        .unwrap();

    assert!(chain.validate_path(&trust_anchor).is_ok());
}

#[test]
fn validate_invalid_chain() {
    init();

    let trust_anchor = Certificate::from_pem(ROOT_CERT).unwrap();
    let mut certificates = read_certs(INVALID_CERT_CHAIN);

    let chain = CertificateChainBuilder::default()
        .set_leaf(certificates.pop().unwrap())
        .set_intermediates(certificates)
        .build()
        .unwrap();

    assert!(chain.validate_path(&trust_anchor).is_err());
}

fn read_certs(mut rd: impl io::BufRead) -> Vec<Certificate> {
    rustls_pemfile::certs(&mut rd)
        .unwrap()
        .iter()
        .map(Certificate::from_der)
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
}
