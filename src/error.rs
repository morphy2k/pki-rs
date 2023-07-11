use crate::certificate;

#[cfg(feature = "signature")]
use crate::signature;

use std::fmt;

use pkcs8::der;

#[derive(Debug)]
pub enum Error {
    /// Certificate error
    Certificate(certificate::Error),

    #[cfg(feature = "signature")]
    /// Signature error
    Signature(signature::Error),

    // SPKI error
    Spki(spki::Error),

    /// PKCS#8 error
    Pkcs8(pkcs8::Error),

    /// ASN.1 DER error
    Ans1(der::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Certificate(err) => write!(f, "certificate error: {}", err),
            #[cfg(feature = "signature")]
            Self::Signature(err) => write!(f, "signature error: {}", err),
            Self::Spki(err) => write!(f, "SPKI error: {}", err),
            Self::Pkcs8(err) => write!(f, "PKCS#8 error: {}", err),
            Self::Ans1(err) => write!(f, "ASN.1 DER error: {}", err),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Certificate(err) => Some(err),
            #[cfg(feature = "signature")]
            Self::Signature(err) => Some(err),
            Self::Spki(err) => Some(err),
            Self::Pkcs8(err) => Some(err),
            Self::Ans1(err) => Some(err),
        }
    }

    fn cause(&self) -> Option<&dyn std::error::Error> {
        self.source()
    }
}

impl From<certificate::Error> for Error {
    fn from(err: certificate::Error) -> Self {
        Self::Certificate(err)
    }
}

#[cfg(feature = "signature")]
impl From<signature::Error> for Error {
    fn from(err: signature::Error) -> Self {
        Self::Signature(err)
    }
}

#[cfg(feature = "signature")]
impl From<::signature::Error> for Error {
    fn from(err: ::signature::Error) -> Self {
        Self::Signature(signature::Error::from(err))
    }
}

impl From<der::Error> for Error {
    fn from(err: der::Error) -> Self {
        Self::Ans1(err)
    }
}

impl From<pkcs8::Error> for Error {
    fn from(err: pkcs8::Error) -> Self {
        Self::Pkcs8(err)
    }
}

impl From<spki::Error> for Error {
    fn from(err: spki::Error) -> Self {
        Self::Spki(err)
    }
}
