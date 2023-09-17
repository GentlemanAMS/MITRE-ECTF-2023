fob: FORCE
	head -c 32 /dev/random > ${SECRETS_DIR}/SECRET_SEED
	head -c 32 /dev/random > ${SECRETS_DIR}/PAIRED_FOB_PAIRING_SIGNING_KEY
	head -c 32 /dev/random > ${SECRETS_DIR}/UNPAIRED_FOB_PAIRING_SIGNING_KEY
#	Create the EEPROM file, since the EEPROM file has a fixed size.
	head -c 2048 /dev/zero > ${EEPROM_PATH}
	rm -f .cargo
	mv cargo/ .cargo/ 2> /dev/null || true
	cargo build --bin ucsc-ectf-fob --release --out-dir /tmp/bld -Z unstable-options
	cp /tmp/bld/ucsc-ectf-fob ${ELF_PATH}
	arm-none-eabi-objcopy -O binary /tmp/bld/ucsc-ectf-fob ${BIN_PATH}

paired_fob: fob
unpaired_fob: fob

FORCE:;
