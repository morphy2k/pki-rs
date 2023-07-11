use crate::Result;

use super::{Certificate, CertificateChain, Error};

use std::{iter, time::SystemTime};

use tracing::{debug, debug_span};
use x509_cert::{ext::pkix::KeyUsages, time::Validity};

impl Certificate {
    pub fn validate_period(&self) -> Result<()> {
        let _span = debug_span!("validate_cert_period").entered();

        let Validity {
            not_before,
            not_after,
        } = self.inner.tbs_certificate.validity;

        debug!(
            not_before = %not_before,
            not_after = %not_after,
            "validating certificate period"
        );

        let now = SystemTime::now();

        if not_before.to_system_time() > now {
            return Err(Error::CertificateImmature)?;
        }

        if not_after.to_system_time() < now {
            return Err(Error::CertificateExpired)?;
        }

        Ok(())
    }
}

impl CertificateChain {
    pub fn validate_period(&self) -> Result<()> {
        let _span = debug_span!("validate_chain_period").entered();

        self.leaf.validate_period()?;

        self.intermediates
            .iter()
            .try_for_each(|cert| cert.validate_period())?;

        Ok(())
    }

    pub fn validate_path(&self, trust_anchor: &Certificate) -> Result<()> {
        let _span =
            debug_span!("validate_path", path_length = self.intermediates.len() + 1).entered();

        let mut chain = iter::once(trust_anchor).chain(self.iter()).peekable();

        let mut path_len_constraints: Vec<Option<u8>> =
            Vec::with_capacity(self.intermediates.len() + 1);

        // 1. For each certificate in the chain
        while let Some(current) = chain.next() {
            let _span2 = debug_span!(
                parent: &_span,
                "current_cert",
                subject = %current.inner.tbs_certificate.subject,
                serial_number = %current.inner.tbs_certificate.serial_number,
            )
            .entered();

            // 1.1. Check the current certificate validity period.
            current.validate_period()?;

            // 1.2. Doing checks against the next certificate in the chain.
            if let Some(next) = chain.peek() {
                let _span3 = debug_span!(
                    parent: &_span2,
                    "next_cert",
                    subject = %next.inner.tbs_certificate.subject,
                    serial_number = %next.inner.tbs_certificate.serial_number,
                )
                .entered();

                // 1.2.1. Check the basic constraints of the current certificate.
                //        If the certificate is a CA certificate, store the path length constraint.
                if let Some(bc) = current.get_basic_constraints() {
                    debug!(
                        is_ca = bc.ca,
                        path_len_constraint = bc.path_len_constraint,
                        "checking basic constraints for current certificate",
                    );
                    if !bc.ca {
                        return Err(Error::BasicConstraintsViolation)?;
                    }

                    path_len_constraints.push(bc.path_len_constraint);
                }

                // 1.2.3. Check the key usage of the current certificate.
                //        If the key usage extension and the keyCertSign bit is present.
                if let Some(ku) = current.get_key_usage() {
                    debug!(
                        key_usage = ?ku.0,
                        "checking key usage for current certificate"
                    );
                    if !ku.0.contains(KeyUsages::KeyCertSign) {
                        return Err(Error::KeyUsageViolation)?;
                    }
                }

                // 1.2.4. Check the issuer of the current certificate
                //        against the subject of the next certificate.
                debug!("comparing issuer and subject");
                if current.inner.tbs_certificate.subject != next.inner.tbs_certificate.issuer {
                    return Err(Error::IssuerSubjectMismatch)?;
                }

                // 1.2.5. Check the subject key identifier of the current certificate
                //        against the authority key identifier of the next certificate.
                if let Some(aki) = next.get_authority_key_identifier() {
                    if let Some(ki) = &aki.key_identifier {
                        if let Some(ski) = current.get_subject_key_identifier() {
                            debug!(
                                "comparing subject key identifier with authority key identifier"
                            );
                            if ki != &ski.0 {
                                return Err(Error::AuthorityKeyIdentifierMismatch)?;
                            }
                        }
                    }

                    if let Some(acsn) = &aki.authority_cert_serial_number {
                        debug!("comparing serial number with authority cert serial number");
                        if acsn != &current.inner.tbs_certificate.serial_number {
                            return Err(Error::AuthorityKeyIdentifierMismatch)?;
                        }
                    }
                }

                // 1.2.6. Check the signature of the next certificate
                //        with the public key of the current certificate.
                current.verify_signature(next)?;
            }
        }

        // 2. Check the path length constraint for the entire chain.
        //    For each CA certificate, ensure that the remaining certificates
        //    in the chain do not exceed its path length constraint.
        debug!("checking path length constraint for the entire chain");
        let path_len = path_len_constraints.len() - 1;
        for (i, v) in path_len_constraints.into_iter().enumerate() {
            if let Some(path_len_constraint) = v {
                if path_len - i > path_len_constraint as usize {
                    return Err(Error::BasicConstraintsViolation)?;
                }
            }
        }

        Ok(())
    }
}
