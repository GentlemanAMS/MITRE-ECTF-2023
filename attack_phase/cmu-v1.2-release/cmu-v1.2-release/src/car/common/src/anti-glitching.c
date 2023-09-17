#include "anti-glitching.h"

/**
 * @brief Enters an infinite loop that requires a reset. 
 * Does so in a fault-injection-tolerant way.
 * THIS FUNCTION IS ONLY EVER CALLED IF WE DETECT A PHYSICALLY
 * IMPOSSIBLE STATE (TRIGGERED BY A HARDWARE FAILURE OR GLITCH)
 */
void halt_and_catch_fire() {
  volatile uint32_t lunkhead = 1;
  while (lunkhead != 2) {
    FI_PROTECT_0("halting_and_catching_fire");
  }
}
