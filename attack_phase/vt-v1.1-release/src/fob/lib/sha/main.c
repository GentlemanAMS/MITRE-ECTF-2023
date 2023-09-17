/** need to choose which SHA implementation to run **/
#define gladman_sha
//#define saddi_sha
//#define mbedtls_sha

/** need to uncomment if the board you are using is MSP432P401R **/
//#define msp432p401r
//#define msp430g2553
#define msp430fr5994
//#define riscv

/// DO NOT EDIT BELOW  //////////////////////////////////////////
#ifdef msp432p401r
#include "msp.h"
#include "rom_map.h"
#include "rom.h"
#include "systick.h"
#endif

#ifdef msp430g2553
#include "msp430.h"
#endif

#ifdef msp430fr5994
#include "msp430.h"
#endif

#include "experiment_time.h"

#include <stdio.h>
#include <string.h>

#ifdef gladman_sha
#include <memory.h>
#include <ctype.h>
#include "gladman/sha2.h"
#endif
#ifdef saddi_sha
#include "saddi/sha256.h"
#include <stdlib.h>
#endif
#ifdef mbedtls_sha
#include "mbedtls/sha256.h"
#endif

#define DIGEST_BYTES (256/8)

/** Globals (test inputs) **/
unsigned char data[] = "abc"; // Data you want to hash
unsigned char check_sha256[] = { 220, 17, 20, 205, 7, 73, 20, 189, 135, 44, 193,
                                 249, 162, 62, 201, 16, 234, 34, 3, 188, 121,
                                 119, 154, 178, 225, 125, 162, 87, 130, 166, 36,
                                 252 }; // Used to verify the hash function
uint8_t hash[DIGEST_BYTES]; // the output of SHA256 will be stored here
size_t len = sizeof(data);

/** contexts **/
#ifdef gladman_sha
sha256_ctx cx[1];
#endif
#ifdef saddi_sha
SHA256_CTX ctx;
#endif
#ifdef mbedtls_sha
mbedtls_sha256_context ctx;
#endif

/** Call initialization functions for different SHA implementations **/
void init_sha()
{
#ifdef gladman_sha
    sha256_begin(cx);
#endif
#ifdef saddi_sha
    sha256_init(&ctx);
#endif
#ifdef mbedtls_aes
    mbedtls_sha256_init(&ctx);
#endif
}

void test_sha256()
{
#ifdef gladman_sha
    sha256(hash, data, len, cx);
#endif
#ifdef saddi_sha
    sha256_update(&ctx, data, len);
    sha256_final(&ctx, hash);
#endif
#ifdef mbedtls_sha
    mbedtls_sha256(data, len, hash, 0, ctx);
#endif
// hash now contains the output of SHA-256
}

//int check_result()
//{
//    return memcmp((uint8_t*) hash, (uint8_t*) check_sha256, DIGEST_BYTES);
//}

int main(int argc, char *argv[])
{

#if defined msp432p401r || defined msp430fr5994
    /** Initialize the board **/
    board_init();

    /** Starting the timer to measure elapsed time **/
    startTimer();
#endif

    /** initialize SHA **/
    init_sha();

    /** test SHA-256 **/
    test_sha256();

    /** Check the result to see whether SHA algorithm is correctly working or not **/
//    volatile unsigned int verify = check_result();

#if defined msp432p401r || defined msp430fr5994
    volatile unsigned int elapsed = getElapsedTime();
#endif

    while (1);

}
