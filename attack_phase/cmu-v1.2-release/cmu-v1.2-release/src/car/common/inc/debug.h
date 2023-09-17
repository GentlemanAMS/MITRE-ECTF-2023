#ifndef DEBUG_PRINT_H
#define DEBUG_PRINT_H

#ifdef DEBUG

// Writes a string literal to the host UART.
// Discards the null terminator.
// This does nothing if DEBUG is not defined.
#define DEBUG_PRINT(STRING_LITERAL) 	\
	do {								\
		uart_write(						\
			HOST_UART,					\
			(uint8_t*)STRING_LITERAL,	\
			sizeof( STRING_LITERAL ));	\
	} while (0)

#else // #ifdef DEBUG

// Writes a string literal to the host UART.
// Discards the null terminator.
// This does nothing if DEBUG is not defined.
#define DEBUG_PRINT(STRING_LITERAL) do {} while (0)

#endif

#endif // #ifndef DEBUG_PRINT_H
