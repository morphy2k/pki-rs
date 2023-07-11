use crate::certificate::Certificate;

use super::Error;

use std::{convert::TryFrom, ops::Add};

use const_oid::AssociatedOid;
use ecdsa::{
    der,
    elliptic_curve::{
        generic_array::ArrayLength,
        sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint},
        AffinePoint, CurveArithmetic, FieldBytesSize, ALGORITHM_OID,
    },
    PrimeCurve,
};
use pkcs8::der::referenced::OwnedToRef;

pub use ecdsa::{Signature, VerifyingKey};

impl<C> TryFrom<&Certificate> for Signature<C>
where
    C: PrimeCurve + AssociatedOid,
    der::MaxSize<C>: ArrayLength<u8>,
    <FieldBytesSize<C> as Add>::Output: Add<der::MaxOverhead> + ArrayLength<u8>,
{
    type Error = Error;

    fn try_from(cert: &Certificate) -> Result<Self, Self::Error> {
        cert.inner
            .signature_algorithm
            .owned_to_ref()
            .assert_oids(ALGORITHM_OID, C::OID)?;

        let bytes = cert
            .inner
            .signature
            .as_bytes()
            .ok_or(signature::Error::new())?;

        Ok(Self::from_der(bytes)?)
    }
}

impl<C> TryFrom<&Certificate> for VerifyingKey<C>
where
    C: PrimeCurve + CurveArithmetic + AssociatedOid,
    FieldBytesSize<C>: ModulusSize,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
{
    type Error = Error;

    fn try_from(cert: &Certificate) -> Result<Self, Self::Error> {
        cert.inner
            .signature_algorithm
            .owned_to_ref()
            .assert_oids(ALGORITHM_OID, C::OID)?;

        let bytes = cert
            .inner
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .as_bytes()
            .ok_or(spki::Error::KeyMalformed)?;

        Ok(Self::from_sec1_bytes(bytes)?)
    }
}
