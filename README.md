# PKI-RS

A (simple) X.509 certificate and trust chain validation library written in pure Rust and  built on [RustCrypto](https://github.com/RustCrypto) crates.

> [!WARNING]
> This is work in progress and not ready for production use. Use at your own risk!

## Supported algorithms

| Algorithm | Supported | Implementation |
| --------- | --------- | -------------- |
| RSA SHA-256 | :x: | |
| RSA SHA-384 | :x: | |
| RSA SHA-512 | :x: | |
| ECDSA NIST P-256 | ✅ | [p256](https://github.com/RustCrypto/elliptic-curves/tree/master/p256) |
| ECDSA NIST P-384 | ✅ | [p384](https://github.com/RustCrypto/elliptic-curves/tree/master/p384) |
| ECDSA NIST P-521 | :x: | |
| EdDSA     | ✅ | [ed25519-dalek](https://github.com/dalek-cryptography/ed25519-dalek) |

## Motivation

Since there is no simple library written in pure Rust to validate and verify X.506 trust chains (as of July 2023), but needed for a personal project, I decided to write one myself, at least as a temporary solution until the development of some [RustCrypto](https://github.com/RustCrypto) crates is completed.
