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
CFLAGSclang=-DTARGET_IS_TM4C123_RB1 -D_FORTIFY_SOURCE=2 -Wformat -Wformat-security -Werror=format-security 
#-ftrivial-auto-var-init=zero  -enable-trivial-auto-var-init-zero-knowing-it-will-be-removed-from-clang                                         
#-fsanitize=cfi -flto -fvisibility=hidden
# fortify source adds preprocessor checks to prevent buffer overflows
#  -fstack-protector adds stack canaries to prevent stack smashing (Disabled because it requires heap memory)
# -fsanitize=kcfi adds kernel control flow integrity checks to prevent kernel exploits
#  -Wformat adds warnings for printf format string vulnerabilities
#  -mbranch-protection=standard adds branch protection to prevent branch prediction attacks

ROOT=.

# Uncomment to enable debug symbols
#DEBUG=1

# add additional directories to search for source files to VPATH
VPATH=${ROOT}/src ${ROOT}/common/src

# add additional directories to search for header files to IPATH
IPATH=${ROOT}/inc ${ROOT}/common/inc

COMPILER=clang

# common/makedefs:
# 	$(error "You need to be using the CMU fork of the build tools!")

# Include common makedefs
include common/makedefs

########################################################
############### START fob customization ################

PLAINTEXT_EEPROM=${SECRETS_DIR}/plaintext_eeprom.bin
ENCRYPTED_EEPROM=${SECRETS_DIR}/eeprom.bin
EEPROM_KEY_FILE=/tmp/addresses.json

# Required for monocypher
CFLAGS+=-Oz -DBLAKE2_NO_UNROLLING
# Oz is the smallest code size optimization level

# check that parameters are defined
check_defined = \
	$(strip $(foreach 1,$1, \
		$(call __check_defined,$1)))
__check_defined = \
	$(if $(value $1),, \
	  $(error Undefined $1))

paired_fob_arg_check:
	$(call check_defined, CAR_ID PAIR_PIN SECRETS_DIR BIN_PATH ELF_PATH EEPROM_PATH)

paired_fob_gen_secret:
	python3 gen_secret.py								\
		--car-id ${CAR_ID}								\
		--pair-pin ${PAIR_PIN}							\
		--secret-file ${SECRETS_DIR}/car_secrets.json	\
		--eeprom-file ${PLAINTEXT_EEPROM}				\
		--paired
	python3 common/scripts/generate-random-h.py		\
		fob											\
		inc/eeprom_otp.h							\
		${EEPROM_KEY_FILE}



unpaired_fob_arg_check:
	$(call check_defined, SECRETS_DIR BIN_PATH ELF_PATH EEPROM_PATH)

unpaired_fob_gen_secret:
	python3 gen_secret.py									\
		--secret-file ${SECRETS_DIR}/car_secrets.json		\
		--eeprom-file ${PLAINTEXT_EEPROM}
	python3 common/scripts/generate-random-h.py		\
		fob											\
		inc/eeprom_otp.h							\
		${EEPROM_KEY_FILE}



################ END fob customization ################
#######################################################

# this rule must come first in `paired_fob`
paired_fob: ${COMPILER}
paired_fob: ${COMPILER}/lib
paired_fob: ${COMPILER}/common/src/tw
paired_fob: paired_fob_arg_check
#paired_fob: cmu_env_check
paired_fob: paired_fob_gen_secret

# this must be the last build rule of `paired_fob`
paired_fob: ${COMPILER}/firmware.axf
paired_fob: copy_artifacts


# this rule must come first in `unpaired_fob`
unpaired_fob: ${COMPILER}
unpaired_fob: ${COMPILER}/lib
unpaired_fob: ${COMPILER}/common/src/tw
unpaired_fob: unpaired_fob_arg_check
#unpaired_fob: cmu_env_check
unpaired_fob: unpaired_fob_gen_secret

# this must be the last build rule of `unpaired_fob`
unpaired_fob: ${COMPILER}/firmware.axf
unpaired_fob: copy_artifacts

# clean all build products
clean:
	@rm -rf ${COMPILER} ${wildcard *~}

# create the output directory
${COMPILER}:
	@mkdir ${COMPILER}

${COMPILER}/lib:
	@mkdir ${COMPILER}/lib

${COMPILER}/common/src/tw:
	@mkdir -p ${COMPILER}/common/src/tw

# for each source file that needs to be compiled besides the file that defines `main`

${COMPILER}/firmware.axf: ${COMPILER}/uart.o
${COMPILER}/firmware.axf: ${COMPILER}/board_link.o
${COMPILER}/firmware.axf: ${COMPILER}/firmware.o
${COMPILER}/firmware.axf: ${COMPILER}/eeprom_access.o

${COMPILER}/firmware.axf: ${COMPILER}/common/src/tw/sysctl.o
${COMPILER}/firmware.axf: ${COMPILER}/common/src/tw/uart.o
${COMPILER}/firmware.axf: ${COMPILER}/common/src/tw/gpio.o
${COMPILER}/firmware.axf: ${COMPILER}/common/src/tw/eeprom.o
${COMPILER}/firmware.axf: ${COMPILER}/common/src/tw/flash.o
${COMPILER}/firmware.axf: ${COMPILER}/common/src/tw/adc.o
${COMPILER}/firmware.axf: ${COMPILER}/common/src/tw/timer.o
${COMPILER}/firmware.axf: ${COMPILER}/common/src/tw/mpu.o
${COMPILER}/firmware.axf: ${COMPILER}/common/src/tw/startup_${COMPILER}.o

${COMPILER}/firmware.axf: ${COMPILER}/common/src/crypto_wrappers.o
${COMPILER}/firmware.axf: ${COMPILER}/common/src/monocypher.o
${COMPILER}/firmware.axf: ${COMPILER}/common/src/hw_rng.o
${COMPILER}/firmware.axf: ${COMPILER}/common/src/timer_config.o
${COMPILER}/firmware.axf: ${COMPILER}/common/src/anti-glitching.o

${ENCRYPTED_EEPROM}: ${PLAINTEXT_EEPROM} ${EEPROM_KEY_FILE}
	python3 /root/common/scripts/pad-firmware-bin.py ${COMPILER}/firmware.bin
	python3 common/scripts/write_eeprom.py		\
		fob										\
		${PLAINTEXT_EEPROM}						\
		${COMPILER}/firmware.bin				\
		${EEPROM_KEY_FILE}						\
		${ENCRYPTED_EEPROM}


copy_artifacts: ${ENCRYPTED_EEPROM}
	rm -f ${EEPROM_PATH}
	python3 /root/common/scripts/pad-firmware-bin.py ${COMPILER}/firmware.bin
	cp ${COMPILER}/firmware.bin ${BIN_PATH}
	cp ${COMPILER}/firmware.axf ${ELF_PATH}
	cp ${ENCRYPTED_EEPROM} ${EEPROM_PATH}
	llvm-strip-13 ${ELF_PATH}

SCATTERclang_firmware=./firmware.ld
ENTRY_firmware=Firmware_Startup

# Include the automatically generated dependency files.
ifneq (${MAKECMDGOALS},clean)
-include ${wildcard ${COMPILER}/*.d} __dummy__
endif
