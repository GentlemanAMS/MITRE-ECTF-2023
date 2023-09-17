NAME := car
TARGET_DIR := ./target/thumbv7em-none-eabi/release
SECRETS_DIR ?= ../deployment
BIN_PATH ?= $(NAME).bin
ELF_PATH ?= $(NAME).elf
EEPROM_PATH ?= $(NAME).eeprom
ifeq ($(BIN_PATH), $(NAME).bin)
# on the host
BUILD_CONTEXT := ../docker_env
else
# in docker
BUILD_CONTEXT := /
endif

CORE := $(BUILD_CONTEXT)/pared_core
LAYOUT := $(BUILD_CONTEXT)/eeprom_layout

all:
	cp .Cargo.toml Cargo.toml
	echo 'pared_core = { path = "$(CORE)" }' >> Cargo.toml
	echo 'eeprom_layout = { path = "$(LAYOUT)" }' >> Cargo.toml
	cargo build --release
	cp $(TARGET_DIR)/$(NAME) $(ELF_PATH)
	cargo objcopy --release -- -O binary $(BIN_PATH).tmp
	dd if=$(BIN_PATH).tmp of=$(BIN_PATH) ibs=32768 skip=1
	rm $(BIN_PATH).tmp
	gen_eeprom car --elf $(ELF_PATH) --secrets $(SECRETS_DIR) --output $(EEPROM_PATH)

clean:
	rm -f *.bin *.elf *.eeprom

car: all

thanos: clean
	cargo clean

