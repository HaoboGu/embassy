# embassy-crypto-driver

`embassy-crypto` provides universal optimized implementations of cryptographic functions,
targeted for embedded systems. This crate defines the driver interface for these functions.

Hardware-agnostic crypto driver unitraits for the Embassy ecosystem.

This crate defines a set of `unitrait!` traits that abstract over
hardware-accelerated (or software) cryptographic operations. Each trait
declares an opaque context type and a set of functions with stable C
linkage symbols, allowing exactly one driver implementation to be selected
at link time.

# Supported Operations

## Digests
- `Md5`, `Sha1`, `Sha224`, `Sha256`, `Sha384`, `Sha512`, `Sha512_224`, `Sha512_256`

## HMAC
- `HmacSha1`, `HmacSha224`, `HmacSha256`, `HmacSha384`, `HmacSha512`, `HmacSha512_224`, `HmacSha512_256`

## Block Ciphers
- `Aes128Ecb`, `Aes256Ecb` — ECB mode
- `Aes128Cbc`, `Aes256Cbc` — CBC mode

## AEAD
- `Aes128Gcm`, `Aes256Gcm` — GCM mode
- `Aes128Ccm`, `Aes256Ccm` — CCM mode

## Elliptic Curve (P256)
- `P256Ecdh` — key generation, public-key derivation, and shared-secret computation for TLS and Bluetooth LE Secure Connections
- `P256Ecdsa` — sign and verify pre-hashed digests for TLS certificate authentication

## Elliptic Curve (P384)
- `P384Ecdh` — key generation, public-key derivation, and shared-secret computation for TLS
- `P384Ecdsa` — sign and verify pre-hashed digests for TLS certificate authentication

## X25519 (Curve25519)
- `X25519` — key generation, public-key derivation, and X25519 shared-secret computation for TLS 1.3 ECDHE

## High-level EC operations
- `P256Ec` — combined P-256 ECDH + ECDSA unitrait serving `embassy-crypto`'s `asymmetric` module
- `P384Ec` — combined P-384 ECDH + ECDSA unitrait serving `embassy-crypto`'s `asymmetric::p384` module

# Driver Registration
A HAL crate registers itself by invoking the generated `*_impl!` macro
for each supported algorithm. Only one crate in the dependency tree may
register a driver for any given algorithm; otherwise linking will fail.