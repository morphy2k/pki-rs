use super::Certificate;

use const_oid::AssociatedOid;
use pkcs8::der::Decode;
use x509_cert::ext::pkix::{
    AuthorityKeyIdentifier, BasicConstraints, CertificatePolicies, ExtendedKeyUsage, KeyUsage,
    SubjectAltName, SubjectKeyIdentifier,
};

pub type Extensions = Vec<Extension>;

#[derive(Debug, Clone)]
pub enum Extension {
    BasicConstraints(BasicConstraints),
    KeyUsage(KeyUsage),
    ExtendedKeyUsage(ExtendedKeyUsage),
    SubjectAlternativeName(SubjectAltName),
    AuthorityKeyIdentifier(AuthorityKeyIdentifier),
    SubjectKeyIdentifier(SubjectKeyIdentifier),
    CertificatePolicies(CertificatePolicies),
}

impl TryFrom<&x509_cert::ext::Extension> for Extension {
    type Error = crate::error::Error;

    fn try_from(value: &x509_cert::ext::Extension) -> Result<Self, Self::Error> {
        let oid = value.extn_id;
        let bytes = value.extn_value.as_bytes();

        let ext = match oid {
            BasicConstraints::OID => Self::BasicConstraints(BasicConstraints::from_der(bytes)?),
            KeyUsage::OID => Self::KeyUsage(KeyUsage::from_der(bytes)?),
            ExtendedKeyUsage::OID => Self::ExtendedKeyUsage(ExtendedKeyUsage::from_der(bytes)?),
            SubjectAltName::OID => Self::SubjectAlternativeName(SubjectAltName::from_der(bytes)?),
            AuthorityKeyIdentifier::OID => {
                Self::AuthorityKeyIdentifier(AuthorityKeyIdentifier::from_der(bytes)?)
            }
            SubjectKeyIdentifier::OID => {
                Self::SubjectKeyIdentifier(SubjectKeyIdentifier::from_der(bytes)?)
            }
            CertificatePolicies::OID => {
                Self::CertificatePolicies(CertificatePolicies::from_der(bytes)?)
            }
            _ => return Err(super::Error::UnsupportedExtension(oid))?,
        };

        Ok(ext)
    }
}

impl Certificate {
    pub fn get_basic_constraints(&self) -> Option<&BasicConstraints> {
        self.parsed_extensions.iter().find_map(|ext| match ext {
            Extension::BasicConstraints(bc) => Some(bc),
            _ => None,
        })
    }

    pub fn get_key_usage(&self) -> Option<&KeyUsage> {
        self.parsed_extensions.iter().find_map(|ext| match ext {
            Extension::KeyUsage(ku) => Some(ku),
            _ => None,
        })
    }

    pub fn get_extended_key_usage(&self) -> Option<&ExtendedKeyUsage> {
        self.parsed_extensions.iter().find_map(|ext| match ext {
            Extension::ExtendedKeyUsage(eku) => Some(eku),
            _ => None,
        })
    }

    pub fn get_subject_alt_name(&self) -> Option<&SubjectAltName> {
        self.parsed_extensions.iter().find_map(|ext| match ext {
            Extension::SubjectAlternativeName(san) => Some(san),
            _ => None,
        })
    }

    pub fn get_authority_key_identifier(&self) -> Option<&AuthorityKeyIdentifier> {
        self.parsed_extensions.iter().find_map(|ext| match ext {
            Extension::AuthorityKeyIdentifier(aki) => Some(aki),
            _ => None,
        })
    }

    pub fn get_subject_key_identifier(&self) -> Option<&SubjectKeyIdentifier> {
        self.parsed_extensions.iter().find_map(|ext| match ext {
            Extension::SubjectKeyIdentifier(ski) => Some(ski),
            _ => None,
        })
    }

    pub fn get_certificate_policies(&self) -> Option<&CertificatePolicies> {
        self.parsed_extensions.iter().find_map(|ext| match ext {
            Extension::CertificatePolicies(cp) => Some(cp),
            _ => None,
        })
    }
}
