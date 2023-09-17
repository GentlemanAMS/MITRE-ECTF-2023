#ifndef CAR_RAND_H
#define CAR_RAND_H

/*
 * Seed the random number generator based on saved seeding
 * information and time, then write a new seed for next power on.
 * Call once before generating random numbers but not at a predictable
 * point after power on.
 */
void seed_rng(void);

#endif