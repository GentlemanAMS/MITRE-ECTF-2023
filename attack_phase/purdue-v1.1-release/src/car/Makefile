#  2023 eCTF
#  Car Makefile
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
# DEBUG=1

# additional base directories
TIVA_ROOT=${ROOT}/lib/tivaware
TIVA_UTILS=${TIVA_ROOT}/utils

# add additional directories to search for source files to VPATH
VPATH=${ROOT}/src
VPATH+=${TIVA_ROOT}
VPATH+=${TIVA_UTILS}

# add additional directories to search for header files to IPATH
IPATH=${ROOT}/inc
IPATH+=${TIVA_ROOT}
IPATH+=${TIVA_UTILS}

# Include common makedefs
include ${TIVA_ROOT}/makedefs


########################################################
############### START car customization ################

# Optimizations
CFLAGS+=-Os
ifdef DEBUG
CFLAGS+=-g -DCDEBUG=1
endif

# check that parameters are defined
check_defined = \
	$(strip $(foreach 1,$1, \
		$(call __check_defined,$1)))
__check_defined = \
	$(if $(value $1),, \
	  $(error Undefined $1))


car_arg_check:
	$(call check_defined, CAR_ID SECRETS_DIR BIN_PATH ELF_PATH EEPROM_PATH)

gen_secret:
ifdef DEBUG
	python3 gen_secret.py --car-id ${CAR_ID} --secret-dir ${SECRETS_DIR} --debug
else
	python3 gen_secret.py --car-id ${CAR_ID} --secret-dir ${SECRETS_DIR}
endif
	mv ${SECRETS_DIR}/${CAR_ID}/eeprom_wrapper.h ${ROOT}/inc/eeprom_wrapper.h

################ END car customization ################
#######################################################


# this rule must come first in `car`
car: ${COMPILER}
car: car_arg_check
car: gen_secret

# these must be the last build rules of `car`
car: ${COMPILER}/firmware.axf
car: copy_artifacts


################ start crypto ################
ASCON_ROOT=${ROOT}/lib/ascon

# # add path to crypto source files to source path
# VPATH+=${ASCON_ROOT}

# # add crypto library to includes path
IPATH+=${ASCON_ROOT}

# # add crypto object file to includes path
# include ${ASCON_ROOT}/makedefs

${ASCON_ROOT}/${COMPILER}/libascon.a:
	${MAKE} -C ${ASCON_ROOT}

ascon: ${ASCON_ROOT}/${COMPILER}/libascon.a

clean_ascon:
	${MAKE} -C ${ASCON_ROOT} clean
################ end crypto ################

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
${COMPILER}/firmware.axf: ${COMPILER}/board_link.o
${COMPILER}/firmware.axf: ${COMPILER}/wrappers.o

ifdef DEBUG
${COMPILER}/firmware.axf: ${COMPILER}/ustdlib.o
endif

${COMPILER}/firmware.axf: ${COMPILER}/firmware.o
${COMPILER}/firmware.axf: ${COMPILER}/cpu_usage.o
${COMPILER}/firmware.axf: ${COMPILER}/startup_${COMPILER}.o
${COMPILER}/firmware.axf: ${TIVA_ROOT}/driverlib/${COMPILER}/libdriver.a
${COMPILER}/firmware.axf: ${ASCON_ROOT}/${COMPILER}/libascon.a

copy_artifacts:
	cp ${COMPILER}/firmware.bin ${BIN_PATH}
	cp ${COMPILER}/firmware.axf ${ELF_PATH}
	cp ${SECRETS_DIR}/${CAR_ID}/eeprom.bin ${EEPROM_PATH}

SCATTERgcc_firmware=${TIVA_ROOT}/firmware.ld
ENTRY_firmware=Firmware_Startup

# Include the automatically generated dependency files.
ifneq (${MAKECMDGOALS},clean)
-include ${wildcard ${COMPILER}/*.d} __dummy__
endif
