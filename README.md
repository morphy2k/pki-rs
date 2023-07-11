# PKI-RS

A (simple) X.509 certificate and trust chain validation library written in pure Rust and  built on [RustCrypto](https://github.com/RustCrypto) crates.

:warning: **This is work in progress and not ready for production use. Use at your own risk!**

## Supported algorithms

| Algorithm | Supported |
| --------- | --------- |
| RSA       | :x: |
| ECDSA     | :heavy_check_mark: |
| EdDSA     | :heavy_check_mark: |

## Motivation

Since there is no simple library written in pure Rust to validate and verify X.506 trust chains (as of July 2023), but needed for a personal project, I decided to write one myself, at least as a temporary solution until the development of some [RustCrypto](https://github.com/RustCrypto) crates is completed.
