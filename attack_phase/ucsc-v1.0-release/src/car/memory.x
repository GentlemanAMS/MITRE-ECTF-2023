MEMORY
{
    TEXT_JUMP  (rx)  :  ORIGIN = 0x00008000,                             LENGTH = 1K
    FLASH      (rx)  :  ORIGIN = ORIGIN(TEXT_JUMP) + LENGTH(TEXT_JUMP),  LENGTH = 110K - LENGTH(TEXT_JUMP)
    STACK      (rw)  :  ORIGIN = 0x20000000,                             LENGTH = 28K
    RAM        (rw)  :  ORIGIN = ORIGIN(STACK) + LENGTH(STACK),          LENGTH = 32K - LENGTH(STACK)
}

/*
Add a block of memory for the stack before the RAM block, so that a stack overflow leaks into
reserved space and flash memory, instead of .data and .bss.
*/

_stack_start = ORIGIN(STACK) + LENGTH(STACK);
