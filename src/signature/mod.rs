#[cfg(feature = "ecdsa")]
pub mod ecdsa;
#[cfg(feature = "ed25519")]
pub mod ed25519;

use crate::{certificate::Certificate, Result};

use std::marker::PhantomData;

use pkcs8::der::{self, Encode};
use signature::Verifier;

// Error type for signature verification
#[derive(Debug)]
pub enum Error {
    /// Malformed signature
    SignatureMalformed,

    /// Signature error
    Signature(signature::Error),

    /// PKCS#8 error
    Pkcs8(pkcs8::Error),

    /// ASN.1 DER error
    Ans1(der::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SignatureMalformed => f.write_str("signature malformed"),
            Self::Signature(err) => write!(f, "signature error: {}", err),
            Self::Pkcs8(err) => write!(f, "PKCS#8 error: {}", err),
            Self::Ans1(err) => write!(f, "ASN.1 DER error: {}", err),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Signature(err) => Some(err),
            Self::Pkcs8(err) => Some(err),
            Self::Ans1(err) => Some(err),
            _ => None,
        }
    }
}

impl From<signature::Error> for Error {
    fn from(err: signature::Error) -> Self {
        Self::Signature(err)
    }
}

impl From<pkcs8::Error> for Error {
    fn from(err: pkcs8::Error) -> Self {
        Self::Pkcs8(err)
    }
}

impl From<der::Error> for Error {
    fn from(err: der::Error) -> Self {
        Self::Ans1(err)
    }
}

impl From<pkcs8::spki::Error> for Error {
    fn from(err: pkcs8::spki::Error) -> Self {
        Self::Pkcs8(pkcs8::Error::PublicKey(err))
    }
}

pub struct SignatureVerifier<V, S>
where
    V: Verifier<S>,
{
    key: V,
    _marker: PhantomData<S>,
}

impl<V, S> SignatureVerifier<V, S>
where
    V: Verifier<S>,
{
    pub fn new(key: V) -> Self {
        Self {
            key,
            _marker: PhantomData,
        }
    }

    #[inline]
    pub fn verify(&self, data: &[u8], signature: &S) -> Result<()> {
        self.key.verify(data, signature)?;

        Ok(())
    }

    pub fn verify_certificate<'a>(&self, cert: &'a Certificate) -> Result<()>
    where
        S: TryFrom<&'a Certificate, Error = Error>,
    {
        let signed_data = cert.inner.tbs_certificate.to_der()?;
        let signature = S::try_from(cert)?;

        self.verify(&signed_data, &signature)?;

        Ok(())
    }
}
