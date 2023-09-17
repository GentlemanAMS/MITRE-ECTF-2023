car: FORCE
	head -c 32 /dev/random > ${SECRETS_DIR}/SECRET_SEED
	head -c 32 /dev/random > ${SECRETS_DIR}/UNLOCK_KEY_ONE
	head -c 32 /dev/random > ${SECRETS_DIR}/UNLOCK_KEY_TWO
#	Create the EEPROM file, since the EEPROM file has a fixed size.
	head -c 2048 /dev/zero > ${EEPROM_PATH}
	rm -f .cargo
	mv cargo/ .cargo/ 2> /dev/null || true
	cargo build --bin ucsc-ectf-car --release --out-dir /tmp/bld -Z unstable-options
	cp /tmp/bld/ucsc-ectf-car ${ELF_PATH}
	arm-none-eabi-objcopy -O binary /tmp/bld/ucsc-ectf-car ${BIN_PATH}

FORCE:;
