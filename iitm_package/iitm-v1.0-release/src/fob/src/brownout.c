#include <stdbool.h>
#include <stdint.h>

#include "brownout.h"

#include "driverlib/sysctl.h"
#include "driverlib/interrupt.h"

/**
 * @brief Set the brownout protection object
 * Brown Out Protections
 * 
 * System Control Reset when tampering is observed 
 */
void set_brownout_protection(void)
{
    SysCtlVoltageEventClear(SysCtlVoltageEventStatus());
    SysCtlVoltageEventConfig(SYSCTL_VEVENT_VDDABO_RST | SYSCTL_VEVENT_VDDBO_RST);

    SysCtlIntRegister(brownout_interrupt);
    IntMasterEnable();
    SysCtlIntEnable(SYSCTL_INT_BOR0 | SYSCTL_INT_VDDA_OK | SYSCTL_INT_USBPLL_LOCK | SYSCTL_INT_PLL_LOCK | SYSCTL_INT_BOR | SYSCTL_INT_BOR1);
}

/**
 * @brief 
 * Cause interrupt which in turn resets device
 */
void brownout_interrupt(void)
{
    SysCtlIntClear(SysCtlIntStatus(SYSCTL_INT_BOR0 | SYSCTL_INT_VDDA_OK | SYSCTL_INT_USBPLL_LOCK | SYSCTL_INT_PLL_LOCK | SYSCTL_INT_BOR | SYSCTL_INT_BOR1));
    SysCtlReset();
}