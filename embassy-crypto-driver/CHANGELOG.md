# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

<!-- next-header -->
## Unreleased - ReleaseDate

### Added
- `P384Ec` high-level unitrait (and `P384EcImpl` / `p384_ec_impl!`), mirroring `P256Ec`
  for P-384: key generation, public-key derivation, ECDH shared secret, and ECDSA
  sign/verify over 48-byte digests. Serves `embassy-crypto`'s `asymmetric::p384` module.
- `P384Signature` type.
- Manual `Default` impls for `P384Scalar` and `P384AffinePoint` (derive is unavailable
  for arrays larger than 32 elements).
- `X25519` driver unitrait (and `X25519Impl` / `x25519_impl!`): key generation,
  public-key derivation, and X25519 shared-secret computation over 32-byte
  RFC 7748 encodings. Serves `embassy-crypto`'s `asymmetric::x25519` module.
- `X25519PrivateKey` and `X25519PublicKey` types.
