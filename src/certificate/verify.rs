use crate::Result;

#[cfg(feature = "signature")]
use crate::signature::SignatureVerifier;

#[cfg(feature = "ed25519")]
use crate::signature::ed25519::{self, ED_25519_OID};

use super::{Certificate, Error};

#[cfg(feature = "ecdsa")]
use ecdsa::{ECDSA_SHA256_OID, ECDSA_SHA384_OID};

#[cfg(feature = "ecdsa")]
use p256::NistP256;

#[cfg(feature = "ecdsa")]
use p384::NistP384;

use pkcs8::der::referenced::OwnedToRef;
use tracing::debug;

impl Certificate {
    /// Verify if given certificate is signed by current certificate
    pub fn verify_signature(&self, cert: &Certificate) -> Result<()> {
        let _span = tracing::trace_span!(
            "verify_signature",
            issuer = %self.inner.tbs_certificate.subject,
            subject = %cert.inner.tbs_certificate.subject,
        )
        .entered();

        let algo = self
            .inner
            .tbs_certificate
            .subject_public_key_info
            .algorithm
            .owned_to_ref();

        // Compare algorithm identifiers
        if algo != cert.inner.signature_algorithm.owned_to_ref() {
            return Err(Error::AlgorithmMismatch)?;
        }

        // Verify signature
        match algo.oid {
            // Ed25519 (RFC 8410)
            #[cfg(feature = "ed25519")]
            ED_25519_OID => {
                debug!("verifying signature with Ed25519 algorithm");
                let key = ed25519::VerifyingKey::try_from(self)?;
                let verifier = SignatureVerifier::new(key);
                verifier.verify_certificate(cert)?;
            }

            // ECDSA with SHA-256 (RFC 5912)
            #[cfg(feature = "ecdsa")]
            ECDSA_SHA256_OID => {
                debug!("verifying signature with ECDSA with SHA-256 algorithm");
                let key = ecdsa::VerifyingKey::<NistP256>::try_from(self)?;
                let verifier = SignatureVerifier::<_, ecdsa::Signature<NistP256>>::new(key);
                verifier.verify_certificate(cert)?;
            }

            // ECDSA with SHA-384 (RFC 5912)
            #[cfg(feature = "ecdsa")]
            ECDSA_SHA384_OID => {
                debug!("verifying signature with ECDSA with SHA-384 algorithm");
                let key = ecdsa::VerifyingKey::<NistP384>::try_from(self)?;
                let verifier = SignatureVerifier::<_, ecdsa::Signature<NistP384>>::new(key);
                verifier.verify_certificate(cert)?;
            }

            // Unsupported
            _ => {
                return Err(Error::AlgorithmUnsupported)?;
            }
        }

        Ok(())
    }
}
