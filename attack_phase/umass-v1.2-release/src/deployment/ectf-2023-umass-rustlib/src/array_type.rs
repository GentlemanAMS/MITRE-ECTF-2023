use core::ops::{Deref, DerefMut};

/*
 * Alignment things:
 * https://rust-lang.github.io/unsafe-code-guidelines/layout/structs-and-tuples.html#c-compatible-layout-repr-c
 * - align(4) guarantees that the entire struct is aligned
 * - repr(C) provides the following points
 * - Position counter starts at 0
 * - 0 is a multiple of 4 so [u8; N] gets placed without padding
 * Therefore, N % 4 == 0 <-> bytemuck cast works without issue
 */
#[repr(C, align(4))]
#[derive(Clone, Copy)]
pub struct AlignedByteArr<const N: usize> (pub [u8; N]);

impl<const N: usize> Deref for AlignedByteArr<N> {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl<const N: usize> DerefMut for AlignedByteArr<N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
impl<const N: usize> AsRef<[u8]> for AlignedByteArr<N> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
impl<const N: usize> AsMut<[u8]> for AlignedByteArr<N> {
    fn as_mut(&mut self) -> &mut[u8] {
        &mut self.0
    }
}

