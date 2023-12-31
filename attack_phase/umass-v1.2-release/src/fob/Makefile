#  2023 eCTF
#  Fob Makefile
#  Kyle Scaplen
#
#  (c) 2023 The MITRE Corporation
#
# This source file is part of an example system for MITRE's 2023 Embedded System CTF (eCTF).
# This code is being provided only for educational purposes for the 2023 MITRE eCTF competition,
# and may not meet MITRE standards for quality. Use this code at your own risk!

# define the part type and base directory - must be defined for makedefs to work
PART=TM4C123GH6PM
CFLAGSgcc=-DTARGET_IS_TM4C123_RB1
ROOT=.

# Uncomment to enable debug symbols
DEBUG=1

# additional base directories
TIVA_ROOT=${SECRETS_DIR}/tivaware
RUST_ROOT=${SECRETS_DIR}/ectf-2023-umass-rustlib

# add additional directories to search for source files to VPATH
VPATH=${ROOT}/src
VPATH+=${TIVA_ROOT}

# add additional directories to search for header files to IPATH
IPATH=${ROOT}/inc
IPATH+=${TIVA_ROOT}

# Include common makedefs
include ${TIVA_ROOT}/makedefs



########################################################
############### START fob customization ################


# Optimizations
CFLAGS+=-Os

CFLAGS+=-DHIDE_FROM_LSP

# check that parameters are defined
check_defined = \
	$(strip $(foreach 1,$1, \
		$(call __check_defined,$1)))
__check_defined = \
	$(if $(value $1),, \
	  $(error Undefined $1))

# TODO: adjust dependency graph depending on if we need precomputation
.PHONY: ${SECRETS_DIR}/precompute_scram_keys/target/release/precompute_scram_keys

${SECRETS_DIR}/precompute_scram_keys/target/release/precompute_scram_keys:
	. ~/.cargo/env && cd ${SECRETS_DIR}/precompute_scram_keys && cargo build --release

paired_fob_arg_check:
	$(call check_defined, CAR_ID PAIR_PIN SECRETS_DIR BIN_PATH ELF_PATH EEPROM_PATH)

paired_fob_gen_secret: ${SECRETS_DIR}/precompute_scram_keys/target/release/precompute_scram_keys
	python3 gen_secret.py --car-id ${CAR_ID} --car-start-base ${SECRETS_DIR}/car_start_base.bin --unpaired-auth-base ${SECRETS_DIR}/unpaired_auth_base.bin --pair-pin ${PAIR_PIN} --header-file inc/secrets.h --eeprom-file ${EEPROM_PATH}


unpaired_fob_arg_check:
	$(call check_defined, SECRETS_DIR BIN_PATH ELF_PATH EEPROM_PATH)

unpaired_fob_gen_secret: ${SECRETS_DIR}/precompute_scram_keys/target/release/precompute_scram_keys
	python3 gen_secret.py --car-start-base ${SECRETS_DIR}/car_start_base.bin --unpaired-auth-base ${SECRETS_DIR}/unpaired_auth_base.bin --header-file inc/secrets.h --eeprom-file ${EEPROM_PATH}


################ END fob customization ################
#######################################################


# this rule must come first in `paired_fob`
paired_fob: ${COMPILER}
paired_fob: paired_fob_arg_check
paired_fob: paired_fob_gen_secret

# this must be the last build rule of `paired_fob`
paired_fob: ${COMPILER}/firmware.axf
paired_fob: copy_artifacts


# this rule must come first in `unpaired_fob`
unpaired_fob: ${COMPILER}
unpaired_fob: unpaired_fob_arg_check
unpaired_fob: unpaired_fob_gen_secret

# this must be the last build rule of `unpaired_fob`
unpaired_fob: ${COMPILER}/firmware.axf
unpaired_fob: copy_artifacts

# Avoid having to enumerate dependencies and let Cargo handle it
.PHONY: ${RUST_ROOT}/target/thumbv7em-none-eabi/release/libectf_2023_umass_rustlib.a

${RUST_ROOT}/target/thumbv7em-none-eabi/release/libectf_2023_umass_rustlib.a:
	. ~/.cargo/env && cd ${RUST_ROOT} && cargo build --release

# build libraries
${TIVA_ROOT}/driverlib/${COMPILER}/libdriver.a:
	${MAKE} -C ${TIVA_ROOT}/driverlib

tivaware: ${TIVA_ROOT}/driverlib/${COMPILER}/libdriver.a

# clean the libraries
clean_tivaware:
	${MAKE} -C ${TIVA_ROOT}/driverlib clean

# clean all build products
clean: clean_tivaware
	@rm -rf ${COMPILER} ${wildcard *~}

# create the output directory
${COMPILER}:
	@mkdir ${COMPILER}


# for each source file that needs to be compiled besides the file that defines `main`

${COMPILER}/firmware.axf: ${COMPILER}/uart.o
${COMPILER}/firmware.axf: ${COMPILER}/board_link.o
${COMPILER}/firmware.axf: ${COMPILER}/firmware.o
${COMPILER}/firmware.axf: ${COMPILER}/startup_${COMPILER}.o
# Put this here because the .a needs to go after the .o
${COMPILER}/firmware.axf: ${RUST_ROOT}/target/thumbv7em-none-eabi/release/libectf_2023_umass_rustlib.a
${COMPILER}/firmware.axf: ${TIVA_ROOT}/driverlib/${COMPILER}/libdriver.a

copy_artifacts:
	cp ${COMPILER}/firmware.bin ${BIN_PATH}
	cp ${COMPILER}/firmware.axf ${ELF_PATH}

SCATTERgcc_firmware=${TIVA_ROOT}/firmware.ld
ENTRY_firmware=Firmware_Startup

# Include the automatically generated dependency files.
ifneq (${MAKECMDGOALS},clean)
-include ${wildcard ${COMPILER}/*.d} __dummy__
endif