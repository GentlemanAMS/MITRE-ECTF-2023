// Adapted from OSU's 2022 eCTF repo.
// All credits are given to them.

#include "entropy.h"
#include "stdbool.h"
#include "stdint.h"
#include "driverlib/systick.h"
#include "driverlib/sysctl.h"
#include "inc/hw_memmap.h"
#include "monocypher.h"

#define ENTROPY_HASH_SIZE 64
#define ENTROPY_DATA_SIZE 16

static union {
    struct {
        uint8_t data[ENTROPY_DATA_SIZE];
        uint8_t pool[ENTROPY_HASH_SIZE - ENTROPY_DATA_SIZE];
    } d;
    uint8_t hash[ENTROPY_HASH_SIZE];
} entropy_data;

static int entropy_data_ptr;

void entropy_init(void) {
    int i;

    SysCtlClockSet(SYSCTL_SYSDIV_2_5 | SYSCTL_USE_PLL | SYSCTL_OSC_MAIN |
                   SYSCTL_XTAL_16MHZ);
    SysTickPeriodSet(0xFFFFFF);
    SysTickEnable();

    for (i = 0; i < 32; i++) {
        add_entropy8(0x12);
        SysCtlDelay(10);
    }
}

void add_entropy8(uint8_t b) {
    int i;
    uint32_t entropy_val;

    __asm__(
        "dsb\r\n"
        "isb\r\n");
    entropy_val = SysTickValueGet() << 8 | b;

    uint8_t message[sizeof(entropy_data.d.pool) + 4];
    for (i = 0; i < sizeof(message) - 4; i++)
        message[i] = entropy_data.d.pool[i];
    for (i = 0; i < 4; i++)
        message[i - 4 + sizeof(message)] = ((uint8_t *)&entropy_val)[i];

    crypto_blake2b(entropy_data.hash, message, sizeof(message));
}

uint8_t get_random8(void) {
    if (entropy_data_ptr >= ENTROPY_DATA_SIZE) {
        add_entropy8(0);
        entropy_data_ptr = 0;
    }
    return entropy_data.d.data[entropy_data_ptr++];
}

void get_random_bytes(uint8_t *buf, uint32_t len) {
    for (int i = 0; i < len; i++) {
        buf[i] = get_random8();
    }
}
