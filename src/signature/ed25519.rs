use crate::certificate::Certificate;

use super::Error;

use const_oid::ObjectIdentifier;
use pkcs8::spki;

pub use ed25519_dalek::{Signature, VerifyingKey};

/// Object identifier for algorithm Ed25519 defined in [RFC 8410](https://www.rfc-editor.org/rfc/rfc8410)
pub(crate) const ED_25519_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");

impl TryFrom<&Certificate> for Signature {
    type Error = Error;

    fn try_from(cert: &Certificate) -> Result<Self, Self::Error> {
        cert.inner
            .signature_algorithm
            .assert_algorithm_oid(ED_25519_OID)?;

        let bytes = cert
            .inner
            .signature
            .as_bytes()
            .ok_or(signature::Error::new())?
            .try_into()
            .map_err(|_| signature::Error::new())?;

        Ok(Self::from_bytes(bytes))
    }
}

impl TryFrom<&Certificate> for VerifyingKey {
    type Error = Error;

    fn try_from(cert: &Certificate) -> Result<Self, Self::Error> {
        cert.inner
            .tbs_certificate
            .subject_public_key_info
            .algorithm
            .assert_algorithm_oid(ED_25519_OID)?;

        let bytes = cert
            .inner
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .as_bytes()
            .ok_or(spki::Error::KeyMalformed)?
            .try_into()
            .map_err(|_| spki::Error::KeyMalformed)?;

        Ok(Self::from_bytes(bytes)?)
    }
}
