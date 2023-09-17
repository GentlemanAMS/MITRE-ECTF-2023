car: .ALWAYS_RUN
	~/.cargo/bin/cargo make -e BUILD_TYPE=release car --verbose >> /dev_out/log_build_car.txt
	cp ../bin/car.bin ${BIN_PATH}
	cp ../bin/car.elf ${ELF_PATH}
	cp ../bin/car.eeprom ${EEPROM_PATH}

unpaired_fob: .ALWAYS_RUN
	~/.cargo/bin/cargo make -e BUILD_TYPE=release unpaired_fob --verbose >> /dev_out/log_build_unpaired_fob.txt
	cp ../bin/fob.bin ${BIN_PATH}
	cp ../bin/fob.elf ${ELF_PATH}
	cp ../bin/unpaired_fob.eeprom ${EEPROM_PATH}

paired_fob: .ALWAYS_RUN
	~/.cargo/bin/cargo make -e BUILD_TYPE=release paired_fob --verbose >> /dev_out/log_build_paired_fob.txt
	cp ../bin/fob.bin ${BIN_PATH}
	cp ../bin/fob.elf ${ELF_PATH}
	cp ../bin/paired_fob.eeprom ${EEPROM_PATH}


.ALWAYS_RUN:
