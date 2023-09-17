/**
 * @file main.c
 * @author Frederich Stine
 * @brief eCTF Car Example Design Implementation
 * @date 2023
 *
 * This source file is part of an example system for MITRE's 2023 Embedded
 * System CTF (eCTF). This code is being provided only for educational purposes
 * for the 2023 MITRE eCTF competition, and may not meet MITRE standards for
 * quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2023 The MITRE Corporation
 */

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "inc/hw_ints.h"
#include "inc/hw_memmap.h"
#include "inc/hw_timer.h"
#include "inc/hw_types.h"

#include "driverlib/eeprom.h"
#include "driverlib/gpio.h"
#include "driverlib/interrupt.h"
#include "driverlib/mpu.h"
#include "driverlib/pin_map.h"
#include "driverlib/sysctl.h"
#include "driverlib/timer.h"

#ifdef HIDE_FROM_LSP
#include "secrets.h"
#else
#define CAR_ID_MACRO 3
#endif

#include "board_link.h"
#include "feature_list.h"
#include "uart.h"

void timer_init(void) {
  SysCtlPeripheralEnable(SYSCTL_PERIPH_WTIMER0);
  TimerConfigure(WTIMER0_BASE, TIMER_CFG_PERIODIC);
  TimerLoadSet64(WTIMER0_BASE, 0xFFFFFFFFFFFFFFFF);
  TimerEnable(WTIMER0_BASE, TIMER_A);

  SysCtlPeripheralEnable(SYSCTL_PERIPH_TIMER1);
  TimerConfigure(TIMER1_BASE, TIMER_CFG_ONE_SHOT);
}

uint64_t timer_get(void) {
  return TimerValueGet64(WTIMER0_BASE);
}
void timer_rtc_start(uint32_t load_value) {
  TimerEnable(TIMER1_BASE, TIMER_A);
  TimerLoadSet(TIMER1_BASE, TIMER_A, load_value);
}
// TivaWare does not provide a function to show whether timer is running, grrrr
bool timer_rtc_is_running() {
  return (HWREG(TIMER1_BASE + TIMER_O_CTL) & TIMER_CTL_TAEN) != 0;
}
void timer_rtc_wait_to_expiry(bool flash_purple) {
  if (!flash_purple) {
    while (timer_rtc_is_running()) {
      // wait
    }
    return;
  }
  int32_t old_color = GPIOPinRead(GPIO_PORTF_BASE, GPIO_PIN_1 | GPIO_PIN_2 | GPIO_PIN_3);

  bool keep_looping = true;
  uint8_t toggle = 0xff;
  while (keep_looping) {
    // Change LED color: purple or off
    GPIOPinWrite(GPIO_PORTF_BASE, GPIO_PIN_1 | GPIO_PIN_2 | GPIO_PIN_3, (GPIO_PIN_1 | GPIO_PIN_2) & toggle); // 123 rbg
    if (!timer_rtc_is_running()) {
      keep_looping = false;
      break;
    };
    for (uint16_t i=0; i<250; i++) {
      SysCtlDelay(10000);
      if (!timer_rtc_is_running()) {
        keep_looping = false;
        break;
      };
    }
    if (!keep_looping) break;
    toggle = ~toggle;
  }
  // Change LED color back
  GPIOPinWrite(GPIO_PORTF_BASE, GPIO_PIN_1 | GPIO_PIN_2 | GPIO_PIN_3, old_color); // 123 rbg
}

// Declare car ID
const uint32_t CAR_ID = CAR_ID_MACRO;

extern void car_main();

/**
 * @brief Main function for the car example
 *
 * Initializes the RF module and waits for a successful unlock attempt.
 * If successful prints out the unlock flag.
 */
int main(void) {
  timer_init();
  // Original configuration
  //SysCtlClockSet(SYSCTL_USE_OSC | SYSCTL_OSC_MAIN | SYSCTL_XTAL_16MHZ);
  // New configuration: 16 MHz -> PLL (400 MHz) -> /5 (bypass /2)
  SysCtlClockSet(SYSCTL_XTAL_16MHZ | SYSCTL_USE_PLL | SYSCTL_SYSDIV_2_5 | SYSCTL_OSC_MAIN | SYSCTL_INT_OSC_DIS);
  // Change LED color: yellow
  GPIOPinWrite(GPIO_PORTF_BASE, GPIO_PIN_1 | GPIO_PIN_2 | GPIO_PIN_3, GPIO_PIN_1 | GPIO_PIN_3); // 123 rbg

  // Initialize UART peripheral
  uart_init();
  // Initialize board link UART
  setup_board_link();

  // Ensure EEPROM peripheral is enabled
  SysCtlPeripheralEnable(SYSCTL_PERIPH_EEPROM0);
  EEPROMInit();

  // Enable MPU to enforce no-execution in SRAM
  // Synchronize data states after region configuration
  // Synchronize both data and instruction states after MPU enabling
  // Synchronization might be overkill but better too much than not enough
  // Region 0: 0x20000000, 32K SRAM (normal)
  MPURegionSet(0, 0x2000000,
               MPU_RGN_SIZE_32K | MPU_RGN_ENABLE |
               MPU_RGN_PERM_NOEXEC | MPU_RGN_PERM_PRV_RW_USR_RW);
  // Region 1: 0x22000000, 32K SRAM (bitbanded)
  MPURegionSet(1, 0x2200000,
               MPU_RGN_SIZE_32K | MPU_RGN_ENABLE |
               MPU_RGN_PERM_NOEXEC | MPU_RGN_PERM_PRV_RW_USR_RW);
  __asm volatile("dsb");
  MPUEnable(MPU_CONFIG_PRIV_DEFAULT | MPU_CONFIG_HARDFLT_NMI);
  __asm volatile("dsb\n isb");

  car_main();
  while (true) {
    // unreachable
  }
}
