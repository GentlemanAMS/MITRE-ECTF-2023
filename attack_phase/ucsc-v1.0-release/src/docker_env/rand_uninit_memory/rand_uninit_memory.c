#pragma GCC diagnostic ignored "-Wuninitialized"
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"

#include "rand_uninit_memory.h"

#define LARGE_STACK_OFFSET 16384 // 16 KiB

unsigned char random_bytes[RANDOM_BYTES_SIZE];

/*

* Safety Justification *

** Relevant sections of the C11 standard (https://www.open-std.org/jtc1/sc22/wg14/www/docs/n1570.pdf) **

6.7.9p10:
If an object that has automatic storage duration is not initialized explicitly, its value is
indeterminate.

6.3.2.1p2:
If the lvalue designates an object of automatic storage duration that could have been
declared with the register storage class (never had its address taken), and that object
is uninitialized (not declared with an initializer and no assignment to it has been
performed prior to use), the behavior is undefined.

3.19.2:
indeterminate value
either an unspecified value or a trap representation

3.19.3:
unspecified value
valid value of the relevant type where this International Standard imposes no
requirements on which value is chosen in any instance

3.19.4:
trap representation
an object representation that need not represent a value of the object type

6.2.6.1p5:
Certain object representations need not represent a value of the object type. If the stored
value of an object has such a representation and is read by an lvalue expression that does
not have character type, the behavior is undefined. If such a representation is produced
by a side effect that modifies all or any part of the object by an lvalue expression that
does not have character type, the behavior is undefined. Such a representation is called
a trap representation.

** Other references **

Defect Report #260, C Committee (https://www.open-std.org/jtc1/sc22/wg14/www/docs/dr_260.htm):
An indeterminate value may be represented by any bit pattern. The C Standard lays down no
requirement that two inspections of the bits representing a given value will observe the same
bit-pattern only that the observed pattern on each occasion will be a valid representation of
the value.

** Justification **

Reading a char of uninitialized memory of automatic storage duration will simply be reading an
indeterminate value under 6.7.9p10 provided that undefined behavior is not triggered under
6.3.2.1p2, which we can guarantee by ensuring we take the address of each char at least once and
that the compiler does not optimize this away. The object is of automatic storage duration, due to
it not being static, thread, or allocated.

An indeterminate value is either an unspecified value or a trap representation under 3.19.2.

If the char is an unspecified value, then under 3.19.3, the char is a valid char.

If the char has a trap representation, then as long as undefined behavior is not triggered under
6.2.6.1p5, the code is safe. Undefined behavior is not triggered under this paragraph because the
lvalue expression we use is of a character type.

There is no other mention of undefined behavior in the C11 standard with regards to an indeterminate
value, unspecified value, or trap representations that are relevant to this code. Therefore, the
reading of a char of uninitialized memory of automatic storage duration and non-register storage
class is not undefined behavior, but results in an indeterminate value, which is valid to read from.

Note that Defect Report #260 states that reading an indeterminate value twice can result in two
different values, so we read each char only once when copying to a global buffer.

To sum up the safety requirements:
- Declare an array of uninitialized characters.
- The uninitialized memory must be of automatic storage duration.
- Take the address of each character at least once.
- Ensure that each character is only read from once.

*/

// Copies uninitialized memory into the random_bytes buffer and calls new_rand_callback at the
// end to allow for the resetting of the uninitialized memory.
void __attribute__((noinline))
init_random_bytes(void (*new_rand_callback)(volatile unsigned char *)) {
    volatile unsigned char uninit_bytes[RANDOM_BYTES_SIZE + LARGE_STACK_OFFSET];

    for (int i = 0; i < RANDOM_BYTES_SIZE; i++) {
        random_bytes[i] = uninit_bytes[i];
    }

    new_rand_callback(uninit_bytes);
}
