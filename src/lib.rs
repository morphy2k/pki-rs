#![forbid(unsafe_code)]
#![warn(rust_2018_idioms)]

pub mod certificate;
pub mod error;

#[cfg(feature = "signature")]
pub mod signature;

pub type Result<T> = std::result::Result<T, error::Error>;
