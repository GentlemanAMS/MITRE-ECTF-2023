//! Constant-time utilities.
use subtle::ConstantTimeEq;

/// Compares two byte arrays of equal length for equality, in constant time.
///
/// Currently uses the [`subtle`] crate's [implementation](`subtle::ConstantTimeEq::ct_eq`) of constant-time equality checking.
///
/// # Examples
///
/// ```
/// use ectf::security::constant_time;
///
/// assert_eq!(constant_time::bytes_equal(&[0, 1, 2, 3], &[0, 1, 2, 3]), true);
/// assert_eq!(constant_time::bytes_equal(&[0, 3, 2, 1], &[0, 1, 2, 3]), false);
/// ```
#[inline(always)]
pub fn bytes_equal<const N: usize>(first: &[u8; N], second: &[u8; N]) -> bool {
    first.ct_eq(second).into()
}

#[cfg(test)]
mod tests {
    use super::bytes_equal;

    #[test]
    fn equal_arrays_return_true() {
        assert_eq!(bytes_equal(b"Hello, World!", b"Hello, World!"), true);
    }

    #[test]
    fn unequal_arrays_return_false() {
        assert_eq!(bytes_equal(b"Hello, World!", b"Goodbye World"), false);
    }
}
