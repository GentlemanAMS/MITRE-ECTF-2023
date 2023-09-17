
/******************************************************************************
 *
 * project.ld - Linker configuration file for project.
 *
 * Copyright (c) 2013-2017 Texas Instruments Incorporated.  All rights reserved.
 * Software License Agreement
 * 
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 * 
 *   Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * 
 *   Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the  
 *   distribution.
 * 
 *   Neither the name of Texas Instruments Incorporated nor the names of
 *   its contributors may be used to endorse or promote products derived
 *   from this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * 
 * This is part of revision 2.1.4.178 of the Tiva Firmware Development Package.
 *
 *****************************************************************************/

_STACK_SIZE = 0x4000;

MEMORY
{
    FLASH    (rx) : ORIGIN = 0x00008000, LENGTH = 0x1B800
    SRAM    (rw) : ORIGIN = 0x20000000, LENGTH = 0x00008000
}

ENTRY(Firmware_Startup)

SECTIONS
{
    .text :
    {
        _text = .;
        KEEP(*(.firmware_startup))
        *(.text*)
        *(.rodata*)
        _etext = .;
    } > FLASH

    .data :
    {
        _data = .;
        _ldata = LOADADDR (.data);
        *(vtable)
        *(.data*)
        _edata = .;
    } > SRAM AT > FLASH

    .bss (NOLOAD) : ALIGN(4)
    {
        _bss = .;
        *(.bss*)
        *(COMMON)
        _ebss = .;
    } > SRAM

    .stack (NOLOAD) : AT(ADDR(.bss) + SIZEOF(.bss))
    {
        . = ALIGN(16);
        . += _STACK_SIZE;
        _stack_top = .;
    } > SRAM

    /DISCARD/ :
    {
      /* Unused exception related info that only wastes space */
      *(.ARM.exidx);
      *(.ARM.exidx.*);
      *(.ARM.extab.*);
    }
}
