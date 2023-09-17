//! Utilities to defend against hardware glitching attacks

#[macro_export]
/// An if-statement that is resistant to glitching.
/// A branch in either direction (condition true/false)
/// will result in an additional check, in order to catch
/// attempts to change control flow.
/// 
/// Note that the condition MUST NOT have any side effects.
/// 
/// # Examples
/// 
/// ```
/// use ectf::double_down_if;
/// 
/// let result = double_down_if!(1 == 1, 3, panic!("Impossible"));
/// assert_eq!(result, 3);
/// ```
/// 
/// ```
/// use ectf::double_down_if;
/// 
/// // 1!=1 should never be true.
/// let result = double_down_if!(1 != 1, panic!("Impossible"), 3);
/// assert_eq!(result, 3);
/// ```
/// 
/// ```
/// use ectf::double_down_if;
/// 
/// // 1==2 should never be true.
/// let result = double_down_if!(1 == 2, 4, 3);
/// assert_eq!(result, 3);
/// ```
macro_rules! double_down_if {
    ($cond:expr, $consequent:expr) => {
        double_down_if!($cond, $consequent, {});
    };
    ($cond:expr, $consequent:expr, $alternate:expr) => {
        if (core::hint::black_box($cond)) {
            if (!(core::hint::black_box($cond))) {
                // PANIC JUSTIFICATION: 
                // With proper use of `double_down_if`, this is impossible
                // unless a hardware fault has occurred.
                panic!("impossible state");
            } else {
                $consequent
            }
        } else {
            if (core::hint::black_box($cond)) {
                // PANIC JUSTIFICATION: 
                // With proper use of `double_down_if`, this is impossible
                // unless a hardware fault has occurred.
                panic!("impossible state");
            } else {
                $alternate
            }
        }
    };
}
