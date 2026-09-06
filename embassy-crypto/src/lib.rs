#![no_std]
#![doc = include_str!("../README.md")]
#![warn(missing_docs)]

#[cfg(feature = "ec")]
pub mod ec;

#[cfg(feature = "p256")]
pub mod p256;

#[cfg(feature = "p384")]
pub mod p384;

mod aes;
mod hash;

pub use aes::*;
pub use hash::*;

pub mod asymmetric;

#[allow(dead_code)]
#[inline]
fn unwrap_inout<'inp, 'out>(
    buf: cipher::inout::InOutBuf<'inp, 'out, u8>,
) -> embassy_crypto_driver::InOutBuf<'inp, 'out, u8> {
    let len = buf.len();
    let (in_ptr, out_ptr) = buf.into_raw();
    unsafe { embassy_crypto_driver::InOutBuf::from_raw(in_ptr, out_ptr, len) }
}
