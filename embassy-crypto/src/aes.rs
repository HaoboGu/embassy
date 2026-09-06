//! AES Operations
//!
//! Every type comes in two forms, selected by its `driver-*` feature:
//!
//! - Feature ON: a type alias for the corresponding RustCrypto type (or a
//!   composition of RustCrypto building blocks over [`Aes128`]/[`Aes256`]),
//!   so the operation runs in software directly.
//! - Feature OFF: a thin wrapper over the `embassy-crypto-driver` unitrait,
//!   served at link time by whichever crate registers the driver (a HAL, an
//!   asm backend, ...).
//!
//! Compositions keep the layering: the mode types are built on
//! [`Aes128`]/[`Aes256`], so a lower layer that stays routed through its
//! unitrait is still accelerated.

use digest::{FixedOutput, Reset};

// ===========================================================================
// ECB block-cipher macro
// ===========================================================================

#[allow(unused_macros)]
macro_rules! impl_ecb {
    (
        $name:ident,
        $drv:path,
        $trait:path,
        $key_size:ty
    ) => {
        /// RustCrypto `BlockCipherEncrypt`/`BlockCipherDecrypt` implementation backed by the embassy-crypto-driver unitrait.
        #[derive(Clone)]
        pub struct $name {
            ctx: <$drv as $trait>::Context,
        }

        impl ::core::fmt::Debug for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                f.debug_struct(stringify!($name)).finish_non_exhaustive()
            }
        }

        impl ::cipher::BlockSizeUser for $name {
            type BlockSize = ::generic_array::typenum::U16;
        }

        impl ::cipher::ParBlocksSizeUser for $name {
            type ParBlocksSize = ::generic_array::typenum::U1;
        }

        impl ::crypto_common::KeySizeUser for $name {
            type KeySize = $key_size;
        }

        impl ::cipher::KeyInit for $name {
            #[inline]
            fn new(key: &::digest::Key<Self>) -> Self {
                Self {
                    ctx: <$drv>::init(key.as_slice().try_into().unwrap()),
                }
            }
        }

        impl ::cipher::BlockCipherEncBackend for $name {
            #[inline]
            fn encrypt_block(&self, block: ::cipher::InOut<'_, '_, ::cipher::Block<Self>>) {
                let (in_ptr, out_ptr) = block.into_raw();
                let buf =
                    unsafe { embassy_crypto_driver::InOutBuf::from_raw(in_ptr as *const u8, out_ptr as *mut u8, 16) };
                <$drv>::encrypt_blocks(&self.ctx, buf);
            }
        }

        impl ::cipher::BlockCipherEncrypt for $name {
            #[inline]
            fn encrypt_with_backend(&self, f: impl ::cipher::BlockCipherEncClosure<BlockSize = Self::BlockSize>) {
                f.call(self);
            }

            #[inline]
            fn encrypt_blocks(&self, blocks: &mut [::cipher::Block<Self>]) {
                if blocks.is_empty() {
                    return;
                }
                let in_ptr = blocks.as_ptr() as *const u8;
                let out_ptr = blocks.as_mut_ptr() as *mut u8;
                let buf = unsafe { embassy_crypto_driver::InOutBuf::from_raw(in_ptr, out_ptr, blocks.len() * 16) };
                <$drv>::encrypt_blocks(&self.ctx, buf);
            }

            #[inline]
            fn encrypt_blocks_inout(&self, blocks: ::cipher::inout::InOutBuf<'_, '_, ::cipher::Block<Self>>) {
                if blocks.is_empty() {
                    return;
                }
                let len = blocks.len() * 16;
                let (in_ptr, out_ptr) = blocks.into_raw();
                let buf =
                    unsafe { embassy_crypto_driver::InOutBuf::from_raw(in_ptr as *const u8, out_ptr as *mut u8, len) };
                <$drv>::encrypt_blocks(&self.ctx, buf);
            }
        }

        impl ::cipher::BlockCipherDecBackend for $name {
            #[inline]
            fn decrypt_block(&self, block: ::cipher::InOut<'_, '_, ::cipher::Block<Self>>) {
                let (in_ptr, out_ptr) = block.into_raw();
                let buf =
                    unsafe { embassy_crypto_driver::InOutBuf::from_raw(in_ptr as *const u8, out_ptr as *mut u8, 16) };
                <$drv>::decrypt_blocks(&self.ctx, buf);
            }
        }

        impl ::cipher::BlockCipherDecrypt for $name {
            #[inline]
            fn decrypt_with_backend(&self, f: impl ::cipher::BlockCipherDecClosure<BlockSize = Self::BlockSize>) {
                f.call(self);
            }

            #[inline]
            fn decrypt_blocks(&self, blocks: &mut [::cipher::Block<Self>]) {
                if blocks.is_empty() {
                    return;
                }
                let in_ptr = blocks.as_ptr() as *const u8;
                let out_ptr = blocks.as_mut_ptr() as *mut u8;
                let buf = unsafe { embassy_crypto_driver::InOutBuf::from_raw(in_ptr, out_ptr, blocks.len() * 16) };
                <$drv>::decrypt_blocks(&self.ctx, buf);
            }

            #[inline]
            fn decrypt_blocks_inout(&self, blocks: ::cipher::inout::InOutBuf<'_, '_, ::cipher::Block<Self>>) {
                if blocks.is_empty() {
                    return;
                }
                let len = blocks.len() * 16;
                let (in_ptr, out_ptr) = blocks.into_raw();
                let buf =
                    unsafe { embassy_crypto_driver::InOutBuf::from_raw(in_ptr as *const u8, out_ptr as *mut u8, len) };
                <$drv>::decrypt_blocks(&self.ctx, buf);
            }
        }
    };
}

// ===========================================================================
// CBC block-cipher macro
// ===========================================================================

#[allow(unused_macros)]
macro_rules! impl_cbc_enc {
    (
        $name:ident,
        $drv:path,
        $trait:path,
        $key_size:ty
    ) => {
        /// RustCrypto `BlockModeEncrypt` implementation backed by the embassy-crypto-driver unitrait.
        pub struct $name {
            ctx: <$drv as $trait>::EncryptContext,
        }

        impl ::core::fmt::Debug for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                f.debug_struct(stringify!($name)).finish_non_exhaustive()
            }
        }

        impl ::cipher::BlockSizeUser for $name {
            type BlockSize = ::generic_array::typenum::U16;
        }

        impl ::cipher::ParBlocksSizeUser for $name {
            type ParBlocksSize = ::generic_array::typenum::U1;
        }

        impl ::crypto_common::KeySizeUser for $name {
            type KeySize = $key_size;
        }

        impl ::cipher::IvSizeUser for $name {
            type IvSize = ::generic_array::typenum::U16;
        }

        impl ::cipher::KeyIvInit for $name {
            #[inline]
            fn new(key: &::digest::Key<Self>, iv: &::cipher::Iv<Self>) -> Self {
                Self {
                    ctx: <$drv>::encrypt_init(
                        key.as_slice().try_into().unwrap(),
                        iv.as_slice().try_into().unwrap(),
                    ),
                }
            }
        }

        impl ::cipher::BlockModeEncBackend for $name {
            #[inline]
            fn encrypt_block(&mut self, block: ::cipher::InOut<'_, '_, ::cipher::Block<Self>>) {
                let (in_ptr, out_ptr) = block.into_raw();
                let buf =
                    unsafe { embassy_crypto_driver::InOutBuf::from_raw(in_ptr as *const u8, out_ptr as *mut u8, 16) };
                <$drv>::encrypt_blocks(&mut self.ctx, buf);
            }
        }

        impl ::cipher::BlockModeEncrypt for $name {
            #[inline]
            fn encrypt_with_backend(&mut self, f: impl ::cipher::BlockModeEncClosure<BlockSize = Self::BlockSize>) {
                f.call(self);
            }

            #[inline]
            fn encrypt_blocks(&mut self, blocks: &mut [::cipher::Block<Self>]) {
                if blocks.is_empty() {
                    return;
                }
                let in_ptr = blocks.as_ptr() as *const u8;
                let out_ptr = blocks.as_mut_ptr() as *mut u8;
                let buf = unsafe { embassy_crypto_driver::InOutBuf::from_raw(in_ptr, out_ptr, blocks.len() * 16) };
                <$drv>::encrypt_blocks(&mut self.ctx, buf);
            }
        }
    };
}

#[allow(unused_macros)]
macro_rules! impl_cbc_dec {
    (
        $name:ident,
        $drv:path,
        $trait:path,
        $key_size:ty
    ) => {
        /// RustCrypto `BlockModeDecrypt` implementation backed by the embassy-crypto-driver unitrait.
        pub struct $name {
            ctx: <$drv as $trait>::DecryptContext,
        }

        impl ::core::fmt::Debug for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                f.debug_struct(stringify!($name)).finish_non_exhaustive()
            }
        }

        impl ::cipher::BlockSizeUser for $name {
            type BlockSize = ::generic_array::typenum::U16;
        }

        impl ::cipher::ParBlocksSizeUser for $name {
            type ParBlocksSize = ::generic_array::typenum::U1;
        }

        impl ::crypto_common::KeySizeUser for $name {
            type KeySize = $key_size;
        }

        impl ::cipher::IvSizeUser for $name {
            type IvSize = ::generic_array::typenum::U16;
        }

        impl ::cipher::KeyIvInit for $name {
            #[inline]
            fn new(key: &::digest::Key<Self>, iv: &::cipher::Iv<Self>) -> Self {
                Self {
                    ctx: <$drv>::decrypt_init(
                        key.as_slice().try_into().unwrap(),
                        iv.as_slice().try_into().unwrap(),
                    ),
                }
            }
        }

        impl ::cipher::BlockModeDecBackend for $name {
            #[inline]
            fn decrypt_block(&mut self, block: ::cipher::InOut<'_, '_, ::cipher::Block<Self>>) {
                let (in_ptr, out_ptr) = block.into_raw();
                let buf =
                    unsafe { embassy_crypto_driver::InOutBuf::from_raw(in_ptr as *const u8, out_ptr as *mut u8, 16) };
                <$drv>::decrypt_blocks(&mut self.ctx, buf);
            }
        }

        impl ::cipher::BlockModeDecrypt for $name {
            #[inline]
            fn decrypt_with_backend(&mut self, f: impl ::cipher::BlockModeDecClosure<BlockSize = Self::BlockSize>) {
                f.call(self);
            }

            #[inline]
            fn decrypt_blocks(&mut self, blocks: &mut [::cipher::Block<Self>]) {
                if blocks.is_empty() {
                    return;
                }
                let in_ptr = blocks.as_ptr() as *const u8;
                let out_ptr = blocks.as_mut_ptr() as *mut u8;
                let buf = unsafe { embassy_crypto_driver::InOutBuf::from_raw(in_ptr, out_ptr, blocks.len() * 16) };
                <$drv>::decrypt_blocks(&mut self.ctx, buf);
            }
        }
    };
}

// ===========================================================================
// GCM AEAD macro
// ===========================================================================

#[allow(unused_macros)]
macro_rules! impl_gcm {
    (
        $name:ident,
        $drv:path,
        $trait:path,
        $key_size:ty
    ) => {
        /// RustCrypto `AeadInPlace` implementation backed by the embassy-crypto-driver unitrait.
        pub struct $name {
            ctx: <$drv as $trait>::Context,
        }

        impl ::core::fmt::Debug for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                f.debug_struct(stringify!($name)).finish_non_exhaustive()
            }
        }

        impl ::crypto_common::KeySizeUser for $name {
            type KeySize = $key_size;
        }

        impl ::cipher::KeyInit for $name {
            #[inline]
            fn new(key: &::digest::Key<Self>) -> Self {
                Self {
                    ctx: <$drv>::init(key.as_slice().try_into().unwrap()),
                }
            }
        }

        impl ::aead::AeadCore for $name {
            type NonceSize = ::generic_array::typenum::U12;
            type TagSize = ::generic_array::typenum::U16;
            const TAG_POSITION: ::aead::TagPosition = ::aead::TagPosition::Postfix;
        }

        impl ::aead::AeadInOut for $name {
            fn encrypt_inout_detached(
                &self,
                nonce: &::aead::Nonce<Self>,
                associated_data: &[u8],
                buffer: ::aead::inout::InOutBuf<'_, '_, u8>,
            ) -> Result<::aead::Tag<Self>, ::aead::Error> {
                let mut tag = ::aead::Tag::<Self>::default();
                <$drv>::encrypt(
                    &self.ctx,
                    nonce.as_slice(),
                    associated_data,
                    crate::unwrap_inout(buffer),
                    tag.as_mut_slice().try_into().unwrap(),
                )
                .map_err(|_| ::aead::Error)?;
                Ok(tag)
            }

            fn decrypt_inout_detached(
                &self,
                nonce: &::aead::Nonce<Self>,
                associated_data: &[u8],
                buffer: ::aead::inout::InOutBuf<'_, '_, u8>,
                tag: &::aead::Tag<Self>,
            ) -> Result<(), ::aead::Error> {
                <$drv>::decrypt(
                    &self.ctx,
                    nonce.as_slice(),
                    associated_data,
                    crate::unwrap_inout(buffer),
                    tag.as_slice().try_into().unwrap(),
                )
                .map_err(|_| ::aead::Error)
            }
        }
    };
}

// ===========================================================================
// CTR stream-cipher wrapper macro
// ===========================================================================

#[allow(unused_macros)]
macro_rules! impl_ctr {
    (
        $name:ident,
        $drv:path,
        $trait:path,
        $key_size:ty
    ) => {
        /// RustCrypto `StreamCipher` implementation backed by the
        /// embassy-crypto-driver unitrait.
        ///
        /// Uses AES-CTR mode with a 128-bit big-endian counter (NIST SP 800-38A).
        /// Encryption and decryption are the same operation.
        pub struct $name {
            ctx: <$drv as $trait>::Context,
        }

        impl ::core::fmt::Debug for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                f.debug_struct(stringify!($name)).finish_non_exhaustive()
            }
        }

        impl ::crypto_common::KeySizeUser for $name {
            type KeySize = $key_size;
        }

        impl ::cipher::IvSizeUser for $name {
            type IvSize = ::generic_array::typenum::U16;
        }

        impl ::cipher::KeyIvInit for $name {
            #[inline]
            fn new(key: &::digest::Key<Self>, iv: &::cipher::Iv<Self>) -> Self {
                Self {
                    ctx: <$drv>::init(
                        key.as_slice().try_into().unwrap(),
                        iv.as_slice().try_into().unwrap(),
                    ),
                }
            }
        }

        impl ::cipher::StreamCipher for $name {
            #[inline]
            fn check_remaining(&self, _data_len: usize) -> Result<(), ::cipher::StreamCipherError> {
                // AES-CTR with a 128-bit counter has 2^128 blocks = 2^132 bytes
                // of keystream before repetition. For any practical embedded
                // buffer this is effectively infinite.
                Ok(())
            }

            #[inline]
            fn unchecked_apply_keystream_inout(&mut self, buf: ::cipher::inout::InOutBuf<'_, '_, u8>) {
                <$drv>::apply_keystream(&mut self.ctx, crate::unwrap_inout(buf));
            }

            #[inline]
            fn unchecked_write_keystream(&mut self, buf: &mut [u8]) {
                buf.fill(0);
                <$drv>::apply_keystream(&mut self.ctx, buf.into());
            }
        }
    };
}

// ===========================================================================
// CMAC macro
// ===========================================================================

#[allow(unused_macros)]
macro_rules! impl_cmac {
    (
        $name:ident,
        $drv:path,
        $trait:path,
        $key_size:ty
    ) => {
        /// RustCrypto `Mac` implementation backed by the embassy-crypto-driver unitrait.
        #[derive(Clone)]
        pub struct $name {
            ctx: <$drv as $trait>::Context,
        }

        impl ::core::fmt::Debug for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                f.debug_struct(stringify!($name)).finish_non_exhaustive()
            }
        }

        impl ::digest::OutputSizeUser for $name {
            type OutputSize = ::generic_array::typenum::U16;
        }

        impl ::crypto_common::KeySizeUser for $name {
            type KeySize = $key_size;
        }

        impl ::cipher::KeyInit for $name {
            #[inline]
            fn new(key: &::digest::Key<Self>) -> Self {
                Self {
                    ctx: <$drv>::init(key.as_slice().try_into().unwrap()),
                }
            }
        }

        impl ::digest::Update for $name {
            #[inline]
            fn update(&mut self, data: &[u8]) {
                <$drv>::update(&mut self.ctx, data);
            }
        }

        impl ::digest::FixedOutput for $name {
            #[inline]
            fn finalize_into(self, out: &mut ::digest::Output<Self>) {
                <$drv>::finalize(self.ctx, out.as_mut_slice().try_into().unwrap());
            }
        }

        impl ::digest::Reset for $name {
            #[inline]
            fn reset(&mut self) {
                <$drv>::reset(&mut self.ctx);
            }
        }

        impl ::digest::FixedOutputReset for $name {
            #[inline]
            fn finalize_into_reset(&mut self, out: &mut ::digest::Output<Self>) {
                self.clone().finalize_into(out);
                self.reset();
            }
        }

        impl ::digest::MacMarker for $name {}
    };
}

// ===========================================================================
// ECB
// ===========================================================================

#[cfg(not(feature = "driver-aes128"))]
impl_ecb!(
    Aes128,
    embassy_crypto_driver::Aes128EcbImpl,
    embassy_crypto_driver::Aes128Ecb,
    ::generic_array::typenum::U16
);

/// AES-128 block cipher: the `aes` crate's software implementation, called
/// directly (no driver unitrait involved).
#[cfg(feature = "driver-aes128")]
pub type Aes128 = ::aes::Aes128;

#[cfg(not(feature = "driver-aes256"))]
impl_ecb!(
    Aes256,
    embassy_crypto_driver::Aes256EcbImpl,
    embassy_crypto_driver::Aes256Ecb,
    ::generic_array::typenum::U32
);

/// AES-256 block cipher: the `aes` crate's software implementation, called
/// directly.
#[cfg(feature = "driver-aes256")]
pub type Aes256 = ::aes::Aes256;

// ===========================================================================
// CBC
// ===========================================================================

#[cfg(not(feature = "driver-aes128cbc"))]
impl_cbc_enc!(
    Aes128CbcEncrypt,
    embassy_crypto_driver::Aes128CbcImpl,
    embassy_crypto_driver::Aes128Cbc,
    ::generic_array::typenum::U16
);

/// AES-128 CBC encryption: RustCrypto CBC mode over [`Aes128`]. When
/// `driver-aes128` is disabled, the block cipher underneath routes through
/// the accelerated `Aes128Ecb` unitrait.
#[cfg(feature = "driver-aes128cbc")]
pub type Aes128CbcEncrypt = ::cbc::Encryptor<Aes128>;

#[cfg(not(feature = "driver-aes128cbc"))]
impl_cbc_dec!(
    Aes128CbcDecrypt,
    embassy_crypto_driver::Aes128CbcImpl,
    embassy_crypto_driver::Aes128Cbc,
    ::generic_array::typenum::U16
);

/// AES-128 CBC decryption: RustCrypto CBC mode over [`Aes128`].
#[cfg(feature = "driver-aes128cbc")]
pub type Aes128CbcDecrypt = ::cbc::Decryptor<Aes128>;

#[cfg(not(feature = "driver-aes256cbc"))]
impl_cbc_enc!(
    Aes256CbcEncrypt,
    embassy_crypto_driver::Aes256CbcImpl,
    embassy_crypto_driver::Aes256Cbc,
    ::generic_array::typenum::U32
);

/// AES-256 CBC encryption: RustCrypto CBC mode over [`Aes256`].
#[cfg(feature = "driver-aes256cbc")]
pub type Aes256CbcEncrypt = ::cbc::Encryptor<Aes256>;

#[cfg(not(feature = "driver-aes256cbc"))]
impl_cbc_dec!(
    Aes256CbcDecrypt,
    embassy_crypto_driver::Aes256CbcImpl,
    embassy_crypto_driver::Aes256Cbc,
    ::generic_array::typenum::U32
);

/// AES-256 CBC decryption: RustCrypto CBC mode over [`Aes256`].
#[cfg(feature = "driver-aes256cbc")]
pub type Aes256CbcDecrypt = ::cbc::Decryptor<Aes256>;

// ===========================================================================
// GCM
// ===========================================================================

#[cfg(not(feature = "driver-aes128gcm"))]
impl_gcm!(
    Aes128Gcm,
    embassy_crypto_driver::Aes128GcmImpl,
    embassy_crypto_driver::Aes128Gcm,
    ::generic_array::typenum::U16
);

/// AES-128 GCM: RustCrypto `AesGcm` over [`Aes128`].
#[cfg(feature = "driver-aes128gcm")]
pub type Aes128Gcm = ::aes_gcm::AesGcm<Aes128, ::generic_array::typenum::U12>;

#[cfg(not(feature = "driver-aes256gcm"))]
impl_gcm!(
    Aes256Gcm,
    embassy_crypto_driver::Aes256GcmImpl,
    embassy_crypto_driver::Aes256Gcm,
    ::generic_array::typenum::U32
);

/// AES-256 GCM: RustCrypto `AesGcm` over [`Aes256`].
#[cfg(feature = "driver-aes256gcm")]
pub type Aes256Gcm = ::aes_gcm::AesGcm<Aes256, ::generic_array::typenum::U12>;

// ===========================================================================
// CCM
// ===========================================================================

#[cfg(not(feature = "driver-aes128ccm"))]
mod aes128ccm {
    use ::aead::common::array::ArraySize;
    use ::aead::inout::InOutBuf;
    use ::aead::{AeadCore, AeadInOut, TagPosition};
    use ::cipher::KeyInit;
    use ::crypto_common::KeySizeUser;
    use ::digest::Key;
    use ::generic_array::typenum::U16;

    /// RustCrypto `AeadInPlace` implementation for AES-128 CCM.
    ///
    /// Generic over `TagSize` (4, 8, or 16) and `NonceSize` (7–13).
    pub struct Aes128Ccm<TagSize, NonceSize> {
        ctx: embassy_crypto_driver::Aes128CcmImplContext,
        _phantom: core::marker::PhantomData<(TagSize, NonceSize)>,
    }

    impl<TagSize, NonceSize> Clone for Aes128Ccm<TagSize, NonceSize> {
        fn clone(&self) -> Self {
            Self {
                ctx: self.ctx.clone(),
                _phantom: core::marker::PhantomData,
            }
        }
    }

    impl<TagSize, NonceSize> core::fmt::Debug for Aes128Ccm<TagSize, NonceSize> {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("Aes128Ccm").finish_non_exhaustive()
        }
    }

    impl<TagSize, NonceSize> KeySizeUser for Aes128Ccm<TagSize, NonceSize> {
        type KeySize = U16;
    }

    impl<TagSize, NonceSize> KeyInit for Aes128Ccm<TagSize, NonceSize> {
        fn new(key: &Key<Self>) -> Self {
            Self {
                ctx: embassy_crypto_driver::Aes128CcmImpl::init(key.as_slice().try_into().unwrap()),
                _phantom: core::marker::PhantomData,
            }
        }
    }

    impl<TagSize, NonceSize> AeadCore for Aes128Ccm<TagSize, NonceSize>
    where
        TagSize: ArraySize,
        NonceSize: ArraySize,
    {
        type NonceSize = NonceSize;
        type TagSize = TagSize;
        const TAG_POSITION: TagPosition = TagPosition::Postfix;
    }

    impl<TagSize, NonceSize> AeadInOut for Aes128Ccm<TagSize, NonceSize>
    where
        TagSize: ArraySize,
        NonceSize: ArraySize,
    {
        fn encrypt_inout_detached(
            &self,
            nonce: &::aead::Nonce<Self>,
            associated_data: &[u8],
            buffer: InOutBuf<'_, '_, u8>,
        ) -> Result<::aead::Tag<Self>, ::aead::Error> {
            let mut tag = ::aead::Tag::<Self>::default();
            embassy_crypto_driver::Aes128CcmImpl::encrypt(
                &self.ctx,
                nonce.as_slice(),
                associated_data,
                crate::unwrap_inout(buffer),
                tag.as_mut_slice(),
            )
            .map_err(|_| ::aead::Error)?;
            Ok(tag)
        }

        fn decrypt_inout_detached(
            &self,
            nonce: &::aead::Nonce<Self>,
            associated_data: &[u8],
            buffer: InOutBuf<'_, '_, u8>,
            tag: &::aead::Tag<Self>,
        ) -> Result<(), ::aead::Error> {
            embassy_crypto_driver::Aes128CcmImpl::decrypt(
                &self.ctx,
                nonce.as_slice(),
                associated_data,
                crate::unwrap_inout(buffer),
                tag.as_slice(),
            )
            .map_err(|_| ::aead::Error)
        }
    }
}

#[cfg(not(feature = "driver-aes128ccm"))]
pub use aes128ccm::Aes128Ccm;

/// AES-128 CCM: RustCrypto `Ccm` over [`Aes128`].
#[cfg(feature = "driver-aes128ccm")]
pub type Aes128Ccm<
    TagSize: ::aead::array::ArraySize + ::ccm::TagSize,
    NonceSize: ::aead::array::ArraySize + ::ccm::NonceSize,
> = ::ccm::Ccm<Aes128, TagSize, NonceSize>;

#[cfg(not(feature = "driver-aes256ccm"))]
mod aes256ccm {
    use ::aead::common::array::ArraySize;
    use ::aead::inout::InOutBuf;
    use ::aead::{AeadCore, AeadInOut, TagPosition};
    use ::cipher::KeyInit;
    use ::crypto_common::KeySizeUser;
    use ::digest::Key;
    use ::generic_array::typenum::U32;

    /// RustCrypto `AeadInPlace` implementation for AES-256 CCM.
    ///
    /// Generic over `TagSize` (4, 8, or 16) and `NonceSize` (7–13).
    pub struct Aes256Ccm<TagSize, NonceSize> {
        ctx: embassy_crypto_driver::Aes256CcmImplContext,
        _phantom: core::marker::PhantomData<(TagSize, NonceSize)>,
    }

    impl<TagSize, NonceSize> Clone for Aes256Ccm<TagSize, NonceSize> {
        fn clone(&self) -> Self {
            Self {
                ctx: self.ctx.clone(),
                _phantom: core::marker::PhantomData,
            }
        }
    }

    impl<TagSize, NonceSize> core::fmt::Debug for Aes256Ccm<TagSize, NonceSize> {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("Aes256Ccm").finish_non_exhaustive()
        }
    }

    impl<TagSize, NonceSize> KeySizeUser for Aes256Ccm<TagSize, NonceSize> {
        type KeySize = U32;
    }

    impl<TagSize, NonceSize> KeyInit for Aes256Ccm<TagSize, NonceSize> {
        fn new(key: &Key<Self>) -> Self {
            Self {
                ctx: embassy_crypto_driver::Aes256CcmImpl::init(key.as_slice().try_into().unwrap()),
                _phantom: core::marker::PhantomData,
            }
        }
    }

    impl<TagSize, NonceSize> AeadCore for Aes256Ccm<TagSize, NonceSize>
    where
        TagSize: ArraySize,
        NonceSize: ArraySize,
    {
        type NonceSize = NonceSize;
        type TagSize = TagSize;
        const TAG_POSITION: TagPosition = TagPosition::Postfix;
    }

    impl<TagSize, NonceSize> AeadInOut for Aes256Ccm<TagSize, NonceSize>
    where
        TagSize: ArraySize,
        NonceSize: ArraySize,
    {
        fn encrypt_inout_detached(
            &self,
            nonce: &::aead::Nonce<Self>,
            associated_data: &[u8],
            buffer: InOutBuf<'_, '_, u8>,
        ) -> Result<::aead::Tag<Self>, ::aead::Error> {
            let mut tag = ::aead::Tag::<Self>::default();
            embassy_crypto_driver::Aes256CcmImpl::encrypt(
                &self.ctx,
                nonce.as_slice(),
                associated_data,
                crate::unwrap_inout(buffer),
                tag.as_mut_slice(),
            )
            .map_err(|_| ::aead::Error)?;
            Ok(tag)
        }

        fn decrypt_inout_detached(
            &self,
            nonce: &::aead::Nonce<Self>,
            associated_data: &[u8],
            buffer: InOutBuf<'_, '_, u8>,
            tag: &::aead::Tag<Self>,
        ) -> Result<(), ::aead::Error> {
            embassy_crypto_driver::Aes256CcmImpl::decrypt(
                &self.ctx,
                nonce.as_slice(),
                associated_data,
                crate::unwrap_inout(buffer),
                tag.as_slice(),
            )
            .map_err(|_| ::aead::Error)
        }
    }
}

#[cfg(not(feature = "driver-aes256ccm"))]
pub use aes256ccm::Aes256Ccm;

/// AES-256 CCM: RustCrypto `Ccm` over [`Aes256`].
#[cfg(feature = "driver-aes256ccm")]
pub type Aes256Ccm<
    TagSize: ::aead::array::ArraySize + ::ccm::TagSize,
    NonceSize: ::aead::array::ArraySize + ::ccm::NonceSize,
> = ::ccm::Ccm<Aes256, TagSize, NonceSize>;

// ===========================================================================
// CTR
// ===========================================================================

#[cfg(not(feature = "driver-aes128ctr"))]
impl_ctr!(
    Aes128Ctr,
    embassy_crypto_driver::Aes128CtrImpl,
    embassy_crypto_driver::Aes128Ctr,
    ::generic_array::typenum::U16
);

/// AES-128 CTR: RustCrypto `Ctr128BE` over [`Aes128`].
#[cfg(feature = "driver-aes128ctr")]
pub type Aes128Ctr = ::ctr::Ctr128BE<Aes128>;

#[cfg(not(feature = "driver-aes256ctr"))]
impl_ctr!(
    Aes256Ctr,
    embassy_crypto_driver::Aes256CtrImpl,
    embassy_crypto_driver::Aes256Ctr,
    ::generic_array::typenum::U32
);

/// AES-256 CTR: RustCrypto `Ctr128BE` over [`Aes256`].
#[cfg(feature = "driver-aes256ctr")]
pub type Aes256Ctr = ::ctr::Ctr128BE<Aes256>;

// ===========================================================================
// CMAC
// ===========================================================================

#[cfg(not(feature = "driver-aes128cmac"))]
impl_cmac!(
    Aes128Cmac,
    embassy_crypto_driver::Aes128CmacImpl,
    embassy_crypto_driver::Aes128Cmac,
    ::generic_array::typenum::U16
);

/// AES-128 CMAC: RustCrypto `Cmac` over [`Aes128`].
#[cfg(feature = "driver-aes128cmac")]
pub type Aes128Cmac = ::cmac::Cmac<Aes128>;

#[cfg(not(feature = "driver-aes256cmac"))]
impl_cmac!(
    Aes256Cmac,
    embassy_crypto_driver::Aes256CmacImpl,
    embassy_crypto_driver::Aes256Cmac,
    ::generic_array::typenum::U32
);

/// AES-256 CMAC: RustCrypto `Cmac` over [`Aes256`].
#[cfg(feature = "driver-aes256cmac")]
pub type Aes256Cmac = ::cmac::Cmac<Aes256>;
