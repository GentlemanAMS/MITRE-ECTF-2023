#include <stdbool.h>
#include <stdint.h>
#include "inc/hw_memmap.h"
#include "driverlib/uart.h"
#include "driverlib/gpio.h"
#include "uart.h"
#include "util.h"
#include "authentication.h"

#define delay(counter) \
    for(size_t i = 0; i < counter; i++);

int main(void) {
    
    //init rand and uart on boot
    uart_init();
    rand_init();
    
    uint32_t first_boot_flag;
    eeprom_read(&first_boot_flag, sizeof(first_boot_flag), EEPROM_FIRST_BOOT_FLAG);

    if(first_boot_flag != 'F') {
        first_boot_flag = 'F';
        eeprom_write(&first_boot_flag, sizeof(first_boot_flag), EEPROM_FIRST_BOOT_FLAG);

        #ifdef DEBUG
        debug_print("first boot");
        #endif
        first_boot();
    }

    secrets_init();
    
    #ifdef DEBUG
    debug_print("car start\n");
    #endif

    reset_state();
    
    // Change LED color: red
    GPIOPinWrite(GPIO_PORTF_BASE, GPIO_PIN_1, GPIO_PIN_1); // r
    GPIOPinWrite(GPIO_PORTF_BASE, GPIO_PIN_2, 0); // b
    GPIOPinWrite(GPIO_PORTF_BASE, GPIO_PIN_3, 0); // g

    while(true) {

        if(UARTCharsAvail(DEVICE_UART)) {

            #ifdef DEBUG
            debug_print("inc message\n");
            #endif

            if(parse_inc_message()) {
                #ifdef DEBUG
                debug_print("sending message\n");
                #endif
                send_next_message();
            }
        }
    }
} 