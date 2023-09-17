use core::mem::size_of;
pub unsafe trait Primitive: Sized {
    const OFFSET: usize;
    const SIZE: usize = size_of::<Self>();
    const SIZE_WORDS: usize = Self::SIZE / size_of::<u32>();

    fn zeroed() -> Self {
        unsafe { core::mem::zeroed() }
    }
    fn as_words_mut(&mut self) -> &mut [u32] {
        let ptr = self as *mut _ as *mut u32;
        let len = Self::SIZE_WORDS;
        unsafe { core::slice::from_raw_parts_mut(ptr, len) }
    }
    fn as_words(&self) -> &[u32] {
        let ptr = self as *const _ as *const u32;
        let len = Self::SIZE_WORDS;
        unsafe { core::slice::from_raw_parts(ptr, len) }
    }
    fn as_bytes_mut(&mut self) -> &mut [u8] {
        let ptr = self as *mut _ as *mut u8;
        let len = Self::SIZE;
        unsafe { core::slice::from_raw_parts_mut(ptr, len) }
    }
    fn as_bytes(&self) -> &[u8] {
        let ptr = self as *const _ as *const u8;
        let len = Self::SIZE;
        unsafe { core::slice::from_raw_parts(ptr, len) }
    }
}

#[macro_export]
macro_rules! impl_primitive {
    ($offset:expr, $t:ty) => {
        sa::assert_eq_align!($t, u32);
        sa::const_assert_eq!(core::mem::size_of::<$t>() % 4, 0);

        unsafe impl Primitive for $t {
            const OFFSET: usize = $offset;
        }
    };
}
