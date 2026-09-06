# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

<!-- next-header -->
## Unreleased - ReleaseDate

### Added
- `asymmetric::x25519`: high-level X25519 (Curve25519) ECDH API (SecretKey /
  PublicKey / SharedSecret), served by the new `X25519` driver unitrait. The
  `driver-x25519` feature runs it in software via `x25519-dalek`, called
  directly, matching the `driver-x` direct-call design.

### Changed
- `driver-x` features now call the RustCrypto crates directly instead of
  registering a RustCrypto-backed driver for the unitrait; the
  `driver-rustcrypto` feature and the `driver_rustcrypto` module have been
  removed. This allows multiple versions of `embassy-crypto` (and the
  RustCrypto trait crates) to be used with a single version of
  `embassy-crypto-driver`. With a `driver-x` feature disabled, the types
  still route through the unitraits, so HAL/asm accelerators keep working
  unchanged.
