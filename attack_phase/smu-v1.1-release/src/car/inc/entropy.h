// Adapted from OSU's 2022 eCTF repo.
// All credits are given to them.

#ifndef ENTROPY_H
#define ENTROPY_H

#include <stdint.h>

void entropy_init(void);
void add_entropy8(uint8_t b);
uint8_t get_random8(void);
void get_random_bytes(uint8_t *buf, uint32_t len);

#endif
