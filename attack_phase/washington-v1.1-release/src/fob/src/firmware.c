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
    
    // do first boot stuff (save keys) if the flag is not set. If it is set, skip it
    uint32_t first_boot_flag;
    eeprom_read(&first_boot_flag, sizeof(first_boot_flag), EEPROM_FIRST_BOOT_FLAG);

    if(first_boot_flag != 'F') {
        first_boot_flag = 'F';
        eeprom_write(&first_boot_flag, sizeof(first_boot_flag), EEPROM_FIRST_BOOT_FLAG);

        first_boot();
    }

    // load secrets from eeprom and use those
    secrets_init();

    // Setup SW1
    GPIOPinTypeGPIOInput(GPIO_PORTF_BASE, GPIO_PIN_4);
    GPIOPadConfigSet(GPIO_PORTF_BASE, GPIO_PIN_4, GPIO_STRENGTH_4MA,
                    GPIO_PIN_TYPE_STD_WPU);

    uint8_t prev_sw_state = GPIO_PIN_4;
    uint8_t curr_sw_state = GPIO_PIN_4;

    // Paired fobs are white
    if(get_dev_type() == TO_P_FOB) {
        // Change LED color: white
        GPIOPinWrite(GPIO_PORTF_BASE, GPIO_PIN_1, GPIO_PIN_1); // r
        GPIOPinWrite(GPIO_PORTF_BASE, GPIO_PIN_2, GPIO_PIN_2); // b
        GPIOPinWrite(GPIO_PORTF_BASE, GPIO_PIN_3, GPIO_PIN_3); // g
    }

    while(true) {
        
        /******************************************************************/
        /*                     Poll for button press                      */ 
        /******************************************************************/
        curr_sw_state = GPIOPinRead(GPIO_PORTF_BASE, GPIO_PIN_4);
        if(curr_sw_state != prev_sw_state && curr_sw_state != 0) {
            delay(1000);
            if(GPIOPinRead(GPIO_PORTF_BASE, GPIO_PIN_4) == curr_sw_state) {
                
                if(get_dev_type() != TO_P_FOB) {
                    #ifdef DEBUG
                    debug_print("not a paired fob");
                    #endif
                }
                else {
                     // On button press
                    #ifdef DEBUG
                    debug_print("button press\n");
                    #endif
                    start_unlock_sequence();
                }
            } 
        }
        prev_sw_state = curr_sw_state;

        /******************************************************************/
         /*                         Fob Stuff                             */
        /******************************************************************/
        if(UARTCharsAvail(DEVICE_UART) && parse_inc_message()) {
            #ifdef DEBUG
            debug_print("inc message\n");
            #endif
            send_next_message();
        }

        /*****************************************************************/
        /*                        Host Stuff                             */
        /*****************************************************************/
        if(UARTCharsAvail(HOST_UART)) {
            handle_host_msg();
        }

    }
}