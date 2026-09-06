# embassy-crypto

RustCrypto trait implementations backed by `embassy-crypto-driver` unitraits.

This crate wraps the hardware-agnostic unitraits from `embassy-crypto-driver`
with the standard RustCrypto traits, so existing RustCrypto code can use
embassy-registered crypto drivers without modification.

# Crate design

- The crate must match closely to the existing rustcrypto API. Deviations from this API
  must have a very good reason that can be clearly explained.
- If a `driver-x` feature is enabled, the corresponding operation is performed by calling
  the RustCrypto crate *directly* — no driver unitrait is involved and no link-time driver
  is registered. If the `driver-x` feature is not enabled, the *embassy-crypto* type is a
  thin layer over the `embassy-crypto-driver` unitrait: any crate (a HAL, an asm backend,
  another software crate) can register the driver, and if none does the binary fails to link.
- The reason for calling RustCrypto directly instead of registering a RustCrypto-backed
  driver for the unitrait (as an earlier design did with a `driver-rustcrypto` module):
  it lets multiple versions of *embassy-crypto* — and therefore multiple versions of the
  RustCrypto trait crates — be used in the same binary with a single version of
  *embassy-crypto-driver*. Registering a driver stakes a link-time global defined in
  *embassy-crypto-driver*; two versions of *embassy-crypto* would both try to define it
  and fail to link. Direct calls stake nothing.
- Composite operations keep layering: e.g. with `driver-aes128cbc` enabled but
  `driver-aes128` disabled, `Aes128CbcEncrypt` is the RustCrypto CBC mode built on
  `Aes128`, which still routes through the accelerated ECB unitrait — so hardware
  acceleration of a lower layer benefits all modes built on top of it. Same for
  `HmacSha256` = `SimpleHmac<Sha256>` when `driver-hmac-sha2` is on but `driver-sha2` is off.
- Given that hardware takes some time to setup, the *embassy-crypto* types should batch
  operations with calls into the unitrait that operate on large buffers where possible.
  At least, the implemented traits or methods should allow the user the possibility of this.

# Supported Operations

## Digests
- `Md5`, `Sha1`, `Sha224`, `Sha256`, `Sha384`, `Sha512`, `Sha512_224`, `Sha512_256`

## HMAC
- `HmacSha1`, `HmacSha224`, `HmacSha256`, `HmacSha384`, `HmacSha512`, `HmacSha512_224`, `HmacSha512_256`

## Block Ciphers
- `Aes128Ecb`, `Aes256Ecb` — ECB mode
- `Aes128Cbc`, `Aes256Cbc` — CBC mode

## Stream Ciphers
- `Aes128Ctr`, `Aes256Ctr` — CTR mode

## AEAD
- `Aes128Gcm`, `Aes256Gcm` — GCM mode
- `Aes128Ccm<TagSize, NonceSize>`, `Aes256Ccm<TagSize, NonceSize>` — CCM mode

## MAC
- `Aes128Cmac`, `Aes256Cmac` — CMAC

## Asymmetric
- `asymmetric` — P-256 ECDH and ECDSA (SecretKey / PublicKey / Signature / SharedSecret)
- `asymmetric::p384` — P-384 ECDH and ECDSA
- `asymmetric::x25519` — X25519 (Curve25519) ECDH

## Elliptic-curve arithmetic
- `ec`, `p256`, `p384` modules — RustCrypto curve trait implementations over driver-accelerated backends

# Digest Usage
```rust,ignore
use embassy_crypto::Sha256;
use digest::Digest;

let mut hasher = Sha256::new();
hasher.update(b"hello world");
let result = hasher.finalize();
```

# HMAC Usage
```rust,ignore
use embassy_crypto::HmacSha256;
use digest::Mac;

let mut mac = HmacSha256::new_from_slice(b"my key").unwrap();
mac.update(b"hello world");
let result = mac.finalize();
```

# Block Cipher Usage
```rust,ignore
use embassy_crypto::Aes128Cbc;
use cipher::{BlockEncryptMut, KeyIvInit};

let mut cipher = Aes128Cbc::new_from_slices(b"my secret key!!!", b"my iv!!!").unwrap();
let mut block = [0u8; 16];
cipher.encrypt_block_mut((&mut block).into());
```

# AEAD Usage
```rust,ignore
use embassy_crypto::Aes128Gcm;
use aead::{Aead, KeyInit, Nonce};

let cipher = Aes128Gcm::new_from_slice(b"my secret key!!!").unwrap();
let nonce = Nonce::from_slice(b"unique nonce");
let ciphertext = cipher.encrypt(nonce, b"plaintext message".as_ref()).unwrap();
```

# Linkage
At link time exactly one crate in the dependency tree must register a driver
using the `embassy_crypto_*_impl!` macros from `embassy-crypto-driver`.
If zero or multiple drivers are registered, linking will fail.

Enabling a `driver-x` feature removes the corresponding unitrait from the link
entirely (RustCrypto is called directly), so no driver needs to be registered
for it.

# `Hkdf` compatibility
When the corresponding `driver-*` feature is enabled, the hash types are the
RustCrypto types themselves, which implement the block-level core that `Hmac`
requires, so `hkdf::Hkdf<Sha256>` works.  With the feature off, the wrapper
only exposes `Update`/`FixedOutput`/`BlockSizeUser` and `Hkdf` will not compile;
only `hkdf::SimpleHkdf<Sha256>` (which uses `SimpleHmac`) is available.

# TODO

- RNG, backed by the MCU peripheral (`embassy-nrf`, `embassy-stm32`, `embassy-rp`, `embassy-mspm0` and `embassy-imxrt` all have one)
- Ed25519 (`ed25519-dalek`), needed by `embassy-boot`; not RustCrypto, so the reference driver rule needs a decision first
- ChaCha20-Poly1305 (`chacha20poly1305`), accelerated by CryptoCell 312
- SHA-3 and SHAKE (`sha3`)
- AES key wrap (`aes-kw`), for moving keys in and out of hardware key stores
- ML-KEM and ML-DSA (`ml-kem`, `ml-dsa`)

HKDF, PBKDF2 and similar constructions are deliberately absent: they are HMAC plus
glue, so `hkdf::SimpleHkdf<Sha256>` over the types here is already accelerated. Note
that `Hkdf<Sha256>` will not compile, only `SimpleHkdf` — `Hmac` requires a block-level
core that these types do not implement.
