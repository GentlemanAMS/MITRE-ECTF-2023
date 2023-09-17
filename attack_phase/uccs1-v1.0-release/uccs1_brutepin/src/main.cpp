#include <Arduino.h>
#include "driverlib/uart.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "driverlib/gpio.h"
#include "driverlib/pin_map.h"
#include "driverlib/sysctl.h"
#include "driverlib/uart.h"

#include "inc/hw_memmap.h"
#include "inc/hw_types.h"
#include "inc/hw_uart.h"

void uart_hosttools_init(void){

    SysCtlPeripheralEnable(SYSCTL_PERIPH_UART0);
    while(!SysCtlPeripheralReady(SYSCTL_PERIPH_UART0));

    //Enable GPIOA Peripheral
    SysCtlPeripheralEnable(SYSCTL_PERIPH_GPIOA);
    while(!SysCtlPeripheralReady(SYSCTL_PERIPH_GPIOA));

    //Configure GPIO pins for RX and TX
    GPIOPinConfigure(GPIO_PA0_U0RX);
    GPIOPinConfigure(GPIO_PA1_U0TX);

    //Configure GPIO and set them up to UART0
    GPIOPinTypeUART(GPIO_PORTA_BASE, GPIO_PIN_0 | GPIO_PIN_1);

    //UART Clock source is system clock
    UARTClockSourceSet(UART0_BASE, UART_CLOCK_SYSTEM);
    
    //Set UART Baud rate
    UARTConfigSetExpClk(UART0_BASE, SysCtlClockGet(), 921600, UART_CONFIG_WLEN_8 | UART_CONFIG_PAR_NONE | UART_CONFIG_STOP_ONE);
    
    //Enable UART
    UARTEnable(UART0_BASE);
}



void setup() {
  uart_hosttools_init();
  pinMode(10, OUTPUT);
  // put your setup code here, to run once:
}

void loop() {
  UARTCharGet(UART0_BASE);
  digitalWrite(10, LOW);
  delayMicroseconds(1000);
  digitalWrite(10, HIGH);
  // put your main code here, to run repeatedly:
}