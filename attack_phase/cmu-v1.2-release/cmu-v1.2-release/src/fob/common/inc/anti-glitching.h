// Anti-glitching protection Macros/Functions

#ifndef ANTI_GLITCHING_H
#define ANTI_GLITCHING_H

#include <stdint.h>
#include "hw_rng.h"


/** @brief Macro that provides weak glitching protection via volatile ints (No Rand Delay)
 *  @param COND conditional to protect
 *  @param ERR_VAL impossible return value from conditional
 *  @return fi_vol, where fi_vol is a global (pre-initialized) volatile int (callled fi_vol)
 */
#define FI_PROT_VOL_WEAK(COND, ERR_VAL) \
	(fi_vol = ERR_VAL); \
	fi_vol = (COND); \
	if (fi_vol == ERR_VAL) halt_and_catch_fire()

/** @brief Macro that provides strong glitching protection via volatile ints + delays
 *  NOTE - SINCE USES RNG, RNG MUST BE INITIALIZED BEFORE USE!
 *  @param COND conditional to protect
 *  @param ERR_VAL impossible return value from conditional
 *  @return fi_vol, where fi_vol is a global (pre-initialized) volatile int (callled fi_vol)
 */
#define FI_PROT_VOL(COND, ERR_VAL) \
	FI_PROT_VOL1(COND, ERR_VAL); \
	FI_PROT_VOL2(ERR_VAL);

/** @brief 1st-part of F1_PROT_VOL to allow secrets to be wiped
 *  @param COND conditional to protect
 *  @param ERR_VAL impossible return value from conditional
 *  @return fi_vol, where fi_vol is a global (pre-initialized) volatile int (callled fi_vol)
 */
#define FI_PROT_VOL1(COND, ERR_VAL) \
	(fi_vol = ERR_VAL); \
	fi_vol = (COND); \
	RAND_STALL()

/** @brief 2-part halting part of FI_PROT_VOL macro
 *  @param ERR_VAL impossible return value from conditional
 *  @return fi_vol, where fi_vol is a global (pre-initialized) volatile int (callled fi_vol)
 */
#define FI_PROT_VOL2(ERR_VAL) \
	if (rand_ret != 1) halt_and_catch_fire(); \
	if (fi_vol == ERR_VAL) halt_and_catch_fire()



// Protect against hairdryer attacks (fault injections)
#define FI_PROTECT_0(ohno) \
    __asm volatile( #ohno ": ");  FI_PROTECT_1(ohno) FI_PROTECT_1(ohno);
#define FI_PROTECT_1(ohno) FI_PROTECT_2(ohno) FI_PROTECT_2(ohno)
#define FI_PROTECT_2(ohno) FI_PROTECT_3(ohno) FI_PROTECT_3(ohno)
#define FI_PROTECT_3(ohno) FI_PROTECT_4(ohno) FI_PROTECT_4(ohno)
#define FI_PROTECT_4(ohno) FI_PROTECT_5(ohno) FI_PROTECT_5(ohno)
#define FI_PROTECT_5(ohno) FI_PROTECT_6(ohno) FI_PROTECT_6(ohno)
#define FI_PROTECT_6(ohno) FI_PROTECT_7(ohno) FI_PROTECT_7(ohno)
#define FI_PROTECT_7(ohno) FI_PROTECT_8(ohno) FI_PROTECT_8(ohno)
#define FI_PROTECT_8(ohno) FI_PROTECT_9(ohno) FI_PROTECT_9(ohno)
#define FI_PROTECT_9(ohno) __asm volatile( "b " #ohno "; " "b " #ohno "; " );

/**
 * @brief Enters an infinite loop that requires a reset. 
 * Does so in a fault-injection-tolerant way.
 * THIS FUNCTION IS ONLY EVER CALLED IF WE DETECT A PHYSICALLY
 * IMPOSSIBLE STATE (TRIGGERED BY A HARDWARE FAILURE OR GLITCH)
 */
void halt_and_catch_fire();

/** @brief Random stall macro - 
 *  Using macro rather than inline to avoid optimization
 *  Delays random number of cycles between 1-255, and checks for skipped values
 */
#define RAND_STALL() \
	rand_ret = -1; \
	rand_ret = fillEntropyBuf(rand_rbt, 2); \
	if (rand_ret == -1) halt_and_catch_fire(); \
	rand_i = 0; \
	rand_y = 0; \
	for (rand_i = 0; rand_i < rand_rbt[0]; rand_i++){ \
		rand_y += 1; \
	} \
	rand_ret = ((rand_i == rand_y) && \
	            (rand_rbt[0] == rand_y))

 /** @brief Halting version of the rand_stall, that halts if glitch detected
  */
#define RAND_STALL_HALT() \
	RAND_STALL(); \
	if (rand_ret != 1) halt_and_catch_fire()

// Evil return codes to compare against with FI_PROT_VOL macros
#define BAD_BOOL (-1)
#define BAD_CRYP_CMP (-2)
#define BAD_RNG (-1)
#define BAD_ENCRYPT (-1)
#define BAD_DECRYPT (-2)
#define BAD_VERIFY (-2)
#define BAD_SIGN (-1)
#define INVALID_CAR_ID (256)
#define INVALID_FEATURE (256)

#endif // #ifndef ANTI_GLITCHING_H

