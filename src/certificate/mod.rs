pub mod extension;
pub mod validate;
pub mod verify;

use crate::Result;

use self::extension::Extensions;

use std::{fmt, slice};

use const_oid::ObjectIdentifier;
use pkcs8::{
    der::{Decode, Encode},
    spki,
};

#[cfg(feature = "pem")]
use pkcs8::der::{DecodePem, EncodePem};

#[derive(Debug)]
pub enum Error {
    /// Certificate not valid yet
    CertificateImmature,

    /// Certificate expired
    CertificateExpired,

    /// Certificate is not valid
    CertificateInvalid,

    /// Algorithm is not supported
    AlgorithmUnsupported,

    /// Algorithm do not match
    AlgorithmMismatch,

    /// Basic constraints violation
    BasicConstraintsViolation,

    /// Key usage violation
    KeyUsageViolation,

    /// Issuer subject name mismatch
    IssuerSubjectMismatch,

    /// Authority key identifier mismatch
    AuthorityKeyIdentifierMismatch,

    /// Unsupported extension
    UnsupportedExtension(ObjectIdentifier),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CertificateImmature => f.write_str("certificate not valid yet"),
            Self::CertificateExpired => f.write_str("certificate expired"),
            Self::CertificateInvalid => f.write_str("certificate invalid"),
            Self::AlgorithmUnsupported => f.write_str("algorithm unsupported"),
            Self::AlgorithmMismatch => f.write_str("algorithm mismatch"),
            Self::BasicConstraintsViolation => f.write_str("basic constraints violation"),
            Self::KeyUsageViolation => f.write_str("key usage violation"),
            Self::IssuerSubjectMismatch => f.write_str("issuer subject name mismatch"),
            Self::AuthorityKeyIdentifierMismatch => {
                f.write_str("authority key identifier mismatch")
            }
            Self::UnsupportedExtension(oid) => {
                write!(f, "unsupported extension: {}", oid)
            }
        }
    }
}

impl std::error::Error for Error {}

#[derive(Clone)]
pub struct Certificate {
    pub(crate) inner: x509_cert::Certificate,
    pub(crate) parsed_extensions: Extensions,
}

impl Certificate {
    pub fn from_der(bytes: impl AsRef<[u8]>) -> Result<Self> {
        x509_cert::Certificate::from_der(bytes.as_ref())?.try_into()
    }

    #[cfg(feature = "pem")]
    pub fn from_pem(pem: impl AsRef<[u8]>) -> Result<Self> {
        x509_cert::Certificate::from_pem(pem)?.try_into()
    }

    pub fn to_der(&self) -> Result<Vec<u8>> {
        Ok(self.inner.to_der()?)
    }

    #[cfg(feature = "pem")]
    pub fn to_pem(&self) -> Result<String> {
        Ok(self.inner.to_pem(pkcs8::LineEnding::LF)?)
    }

    pub fn validity(&self) -> x509_cert::time::Validity {
        self.inner.tbs_certificate.validity
    }

    pub fn issuer(&self) -> String {
        self.inner.tbs_certificate.issuer.to_string()
    }

    pub fn subject(&self) -> String {
        self.inner.tbs_certificate.subject.to_string()
    }

    pub fn serial_bytes(&self) -> &[u8] {
        self.inner.tbs_certificate.serial_number.as_bytes()
    }

    pub fn serial_string(&self) -> String {
        self.inner.tbs_certificate.serial_number.to_string()
    }

    #[cfg(feature = "fingerprint")]
    pub fn fingerprint_base64(&self) -> Result<String> {
        let fp = self
            .inner
            .tbs_certificate
            .subject_public_key_info
            .fingerprint_base64()?;

        Ok(fp)
    }

    pub fn public_key_bytes(&self) -> Result<&[u8]> {
        let bytes = self
            .inner
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .as_bytes()
            .ok_or(spki::Error::KeyMalformed)?;

        Ok(bytes)
    }

    pub fn inner(&self) -> &x509_cert::Certificate {
        &self.inner
    }
}

impl fmt::Debug for Certificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Certificate")
            .field("inner", &self.inner)
            .field("extensions", &self.parsed_extensions)
            .finish()
    }
}

impl TryFrom<x509_cert::Certificate> for Certificate {
    type Error = crate::error::Error;

    fn try_from(cert: x509_cert::Certificate) -> std::result::Result<Self, Self::Error> {
        let ext = cert
            .tbs_certificate
            .extensions
            .as_deref()
            .unwrap_or_default()
            .iter()
            .filter_map(|ext| match ext.try_into() {
                Ok(v) => Some(Ok(v)),
                Err(_) if !ext.critical => None,
                Err(err) => Some(Err(err)),
            })
            .collect::<std::result::Result<_, _>>()?;

        Ok(Self {
            inner: cert,
            parsed_extensions: ext,
        })
    }
}

#[derive(Debug, Clone)]
pub struct CertificateChain {
    intermediates: Vec<Certificate>,
    leaf: Certificate,
}

impl<'a> CertificateChain {
    pub fn new(intermediates: Vec<Certificate>, leaf: Certificate) -> Self {
        Self {
            intermediates,
            leaf,
        }
    }

    pub fn intermediates(&self) -> &[Certificate] {
        &self.intermediates
    }

    pub fn leaf(&self) -> &Certificate {
        &self.leaf
    }

    pub fn iter(&'a self) -> CertificateChainIter<'a> {
        CertificateChainIter {
            intermediates: self.intermediates.iter(),
            leaf: Some(&self.leaf),
        }
    }
}

pub struct CertificateChainIter<'a> {
    intermediates: slice::Iter<'a, Certificate>,
    leaf: Option<&'a Certificate>,
}

impl<'a> Iterator for CertificateChainIter<'a> {
    type Item = &'a Certificate;

    fn next(&mut self) -> Option<Self::Item> {
        self.intermediates.next().or_else(|| self.leaf.take())
    }
}

impl<'a> DoubleEndedIterator for CertificateChainIter<'a> {
    fn next_back(&mut self) -> Option<Self::Item> {
        self.leaf.take().or_else(|| self.intermediates.next_back())
    }
}

pub struct CertificateChainBuilder<State>(State);

impl Default for CertificateChainBuilder<WantsLeaf> {
    fn default() -> Self {
        Self(WantsLeaf(()))
    }
}

pub struct WantsLeaf(());

impl CertificateChainBuilder<WantsLeaf> {
    /// Set the leaf certificate
    pub fn set_leaf(
        self,
        cert: impl Into<Certificate>,
    ) -> CertificateChainBuilder<WantsIntermediates> {
        CertificateChainBuilder(WantsIntermediates { leaf: cert.into() })
    }
}

pub struct WantsIntermediates {
    leaf: Certificate,
}

impl CertificateChainBuilder<WantsIntermediates> {
    /// Set the intermediate certificates
    pub fn set_intermediates(
        self,
        certs: impl IntoIterator<Item = impl Into<Certificate>>,
    ) -> CertificateChainBuilder<Optional> {
        CertificateChainBuilder(Optional {
            leaf: self.0.leaf,
            intermediates: certs.into_iter().map(Into::into).collect(),
        })
    }
}

pub struct Optional {
    leaf: Certificate,
    intermediates: Vec<Certificate>,
}

impl CertificateChainBuilder<Optional> {
    /// Add additional intermediate certificates
    pub fn add_intermediates(
        mut self,
        certs: impl IntoIterator<Item = impl Into<Certificate>>,
    ) -> Self {
        self.0
            .intermediates
            .extend(certs.into_iter().map(Into::into));
        self
    }

    /// Build the certificate chain
    pub fn build(self) -> Result<CertificateChain> {
        let chain = CertificateChain::new(self.0.intermediates, self.0.leaf);

        Ok(chain)
    }
}
