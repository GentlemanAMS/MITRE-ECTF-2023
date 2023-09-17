OUTPUT = librand_uninit_memory.a
SOURCEFILES = $(wildcard *.c)
OBJECTFILES = $(patsubst %.c,%.o,$(SOURCEFILES))

PREFIX = arm-none-eabi
CC = $(PREFIX)-gcc
AR = $(PREFIX)-ar
CFLAGS = -Wall -Werror -Wextra -pedantic -Wstack-usage=18432 -std=gnu11 -mthumb -mabi=aapcs -O3

.PHONY: all debug clean format

all: $(OUTPUT)

$(OUTPUT): $(OBJECTFILES)
	$(AR) -crs $@ $^

$(OBJECTFILES): $(SOURCEFILES)
	$(CC) $(CFLAGS) -c $(SOURCEFILES)

debug: CFLAGS += -g
debug: all

clean:
	rm -f $(OUTPUT) $(OBJECTFILES)

format:
	clang-format -i -style=file *.[ch]
