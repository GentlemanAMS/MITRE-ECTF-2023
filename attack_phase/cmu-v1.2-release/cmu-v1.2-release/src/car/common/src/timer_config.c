#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include "tw/sysctl.h"
#include "tw/timer.h"
#include "tw/hw/hw_memmap.h"

#include "timer_config.h"

// Timer helpers

// Equivalent to (FREQ / 1000) * 4300
#define TIMEOUT_MIN_700MS(FREQ) ((FREQ / 10) * 43)
// Equivalent to (FREQ / 1000) * 600
#define TIMEOUT_MIN_4400MS(FREQ) ((FREQ / 10) * 6)
#define TIMEOUT_5_SEC(FREQ) (FREQ * 5)



// A long ~5 sec timeout
void attacked_stall()
{
  // Ensure timer hasn't reset, and that timer counted down by 4400ms
  while ((TimerValueGet(WTIMER0_BASE, TIMER_A) > TIMEOUT_MIN_4400MS(SysCtlClockGet())) &&
         (TimerIntStatus(WTIMER0_BASE, TIMER_TIMA_TIMEOUT) == 0)) {}
  TimerDisable(WTIMER0_BASE, TIMER_A);
}

// normal operation min timeout
void normal_stall()
{
  // Ensure timer hasn't reset, and that timer counted down by 700ms
  while ((TimerValueGet(WTIMER0_BASE, TIMER_A) > TIMEOUT_MIN_700MS(SysCtlClockGet())) &&
         (TimerIntStatus(WTIMER0_BASE, TIMER_TIMA_TIMEOUT) == 0)) {}
  TimerDisable(WTIMER0_BASE, TIMER_A);
}

// Load timer w/ new wait period
void prime_delay_timer()
{
  TimerLoadSet(WTIMER0_BASE, TIMER_A, TIMEOUT_5_SEC(SysCtlClockGet()));
  TimerIntClear(WTIMER0_BASE, TIMER_TIMA_TIMEOUT);
  TimerEnable(WTIMER0_BASE, TIMER_A);
}

// init timers
int init_timers()
{
  //error case
  volatile int ret = -2;

  // Configure one-shot timer0
  SysCtlPeripheralEnable(SYSCTL_PERIPH_WTIMER0);
  TimerConfigure(WTIMER0_BASE, TIMER_CFG_A_ONE_SHOT);
  TimerIntEnable(WTIMER0_BASE, TIMER_TIMA_TIMEOUT);
  ret++;

  // Enable timer1 which will be used for uart timeouts. (will be loaded separately).
  SysCtlPeripheralEnable(SYSCTL_PERIPH_WTIMER1);
  TimerConfigure(WTIMER1_BASE, TIMER_CFG_A_ONE_SHOT);
  TimerIntEnable(WTIMER1_BASE, TIMER_TIMA_TIMEOUT);
  ret++;
  
  return ret;
}
