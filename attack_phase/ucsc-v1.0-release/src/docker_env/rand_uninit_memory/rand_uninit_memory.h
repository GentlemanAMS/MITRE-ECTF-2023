#pragma once

#define RANDOM_BYTES_SIZE 1024

extern unsigned char random_bytes[RANDOM_BYTES_SIZE];

// Requires at least 18K of stack memory to function, not including the callback's memory. The
// caller must guarantee this function is never inlined across FFI boundaries.
void init_random_bytes(void (*new_rand_callback)(volatile unsigned char *));
