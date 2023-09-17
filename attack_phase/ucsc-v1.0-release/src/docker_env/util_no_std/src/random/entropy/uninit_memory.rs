use crate::{random::fill_rand_slice_secondary, RuntimePeripherals};
use core::{ffi::c_uchar, marker::PhantomData, mem::MaybeUninit};

use rand_chacha::{
    rand_core::{RngCore, SeedableRng},
    ChaCha20Rng,
};

use super::EntropySource;
use sha3::{Digest, Sha3_256};

/// Gets the size of the uninitialized memory buffer from the rand_uninit_memory library header file.
const fn get_random_bytes_size() -> usize {
    const FILE: &str = include_str!("../../../../rand_uninit_memory/rand_uninit_memory.h");

    let mut file_idx = 0;
    let mut line_len;
    let mut line_buff = [0; FILE.len()];
    let eq_check = b"#define RANDOM_BYTES_SIZE ";

    'outer: while file_idx < FILE.len() {
        line_len = 0;

        // Get each line and put it in line_buff.
        while file_idx < FILE.len() && FILE.as_bytes()[file_idx] != b'\n' {
            line_buff[line_len] = FILE.as_bytes()[file_idx];

            line_len += 1;
            file_idx += 1;
        }

        file_idx += 1;

        // This means we don't have enough bytes for this line to be the one.
        // Or it had too many to be valid (more than 20 characters).
        if line_len <= eq_check.len() || line_len > eq_check.len() + 20 {
            continue;
        }

        let mut line_idx = 0;

        // Check if our line begins with eq_check.
        while line_idx < eq_check.len() {
            if line_buff[line_idx] != eq_check[line_idx] {
                continue 'outer;
            }

            line_idx += 1;
        }

        let mut num = 0;

        // Now, we just need to get the number if there is one.
        while line_idx < line_len {
            if !line_buff[line_idx].is_ascii_digit() {
                continue 'outer;
            }

            num = num * 10 + (line_buff[line_idx] - b'0') as usize;

            line_idx += 1;
        }

        assert!(
            num == 1024,
            "Our old size was 1024. Now it is not. Did you mean to do this?"
        );

        return num;
    }

    panic!("Bad header file. No size present.");
}

/// The size of the uninitialized memory buffer.
const RANDOM_BYTES_SIZE: usize = get_random_bytes_size();

// Get functions/variables from the rand_uninit_memory library.
#[link(name = "rand_uninit_memory", kind = "static")]
extern "aapcs" {
    /// The copied uninitialized memory buffer.
    static mut random_bytes: [c_uchar; RANDOM_BYTES_SIZE];

    /// Copies uninitialized memory into the random_bytes buffer and calls new_rand_callback at the
    /// end to allow for the resetting of the uninitialized memory.
    fn init_random_bytes(new_rand_callback: unsafe extern "aapcs" fn(*mut MaybeUninit<c_uchar>));
}

/// This is the callback function passed into the init_random_bytes function. The callback function is
/// used to set the uninitialized stack memory to a new set of random values so that on the next CPU
/// reset without a power cycle, there will be a new set of random "uninitialized" memory.
///
/// We generate a SHA3-256 hash of the uninitialized memory and use it to seed a ChaCha20 CSPRNG, which
/// will generate uniform random numbers used to set the uninitialized memory for the next CPU reset.
///
/// Safety:
/// uninit_memory must be a valid pointer that points to an array of unsigned chars of size
/// RANDOM_BYTES_SIZE or higher.
///
/// random_bytes may only be modified on one thread.
///
/// random_bytes must be fully initialized and be of size RANDOM_BYTES_SIZE or higher.
///
/// This function can only be run on the same thread that random_bytes is modified on.
#[no_mangle]
unsafe extern "aapcs" fn new_rand_callback(uninit_memory: *mut MaybeUninit<c_uchar>) {
    // Generate random bytes using the secondary RNG.
    const SECONDARY_RNG_NUM_BYTES: usize = 32;
    let mut secondary_rng_rand_bytes = [0; SECONDARY_RNG_NUM_BYTES];
    fill_rand_slice_secondary(&mut secondary_rng_rand_bytes);

    // Hash the secondary RNG random bytes and the uninitialized memory.
    let mut seed_hasher = Sha3_256::new();
    seed_hasher.update(secondary_rng_rand_bytes);
    // SAFETY: The use of random_bytes is data-race-free due to the guarantees provided by this
    // function. Since random_bytes is fully initialized and is data-race-free, this use of
    // random_bytes is safe.
    seed_hasher.update(random_bytes);
    let seed_hash = seed_hasher.finalize();

    // Replace the old uninitialized memory with random bytes.
    let mut uninit_memory_rng = ChaCha20Rng::from_seed(seed_hash.into());

    for i in 0..RANDOM_BYTES_SIZE {
        // SAFETY: The use of add() is safe because the size of uninit_memory is RANDOM_BYTES_SIZE
        // or higher, and we are only adding by a maximum of RANDOM_BYTES_SIZE - 1. We are adding a
        // byte offset to a C unsigned char pointer. A C unsigned char is one byte. Therefore,
        // incrementing the byte offset by one each iteration is safe.
        // SAFETY: The use of write_volatile() is safe because the pointer is always valid assuming the
        // uninit_memory pointer + offset is valid.
        uninit_memory
            .add(i)
            .write_volatile(MaybeUninit::new(uninit_memory_rng.next_u32() as u8));
    }
}

/// This entropy source gathers entropy from uninitialized memory.
pub(crate) struct UninitMemory<T: EntropySource> {
    next: T,
    remove_send_sync: PhantomData<*const ()>, // Prevents UninitMemory from being Send or Sync.
}

impl<T: EntropySource> EntropySource for UninitMemory<T> {
    fn init(peripherals: &mut RuntimePeripherals) -> Self {
        unsafe {
            // SAFETY: This function call is safe due to the previous safety justifications on
            // init_random_bytes() and new_rand_callback().
            init_random_bytes(new_rand_callback);
        }

        UninitMemory {
            next: T::init(peripherals),
            remove_send_sync: PhantomData,
        }
    }

    fn add_to_hasher(&self, hasher: &mut Sha3_256) {
        // SAFETY: This read from random_bytes is safe because UninitMemory is neither Send nor Sync,
        // and therefore, it can only be accessed on the thread it was initialized on.
        hasher.update(unsafe { &random_bytes });
        self.next.add_to_hasher(hasher);
    }
}
