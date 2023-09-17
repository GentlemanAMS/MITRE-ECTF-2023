#  2023 eCTF
#  Secure Car Makefile
#  Spartan State Security Team
#
#  This source file is part of our designed system
#  for MITRE's 2023 Embedded System CTF (eCTF).

# define the part type and base directory - must be defined for makedefs to work
PART=TM4C123GH6PM
CFLAGSgcc=-DTARGET_IS_TM4C123_RB1
ROOT=.

# additional base directories
TIVA_ROOT=${ROOT}/lib/tivaware

# add additional directories to search for source files to VPATH
VPATH=${ROOT}/src
VPATH+=${TIVA_ROOT}

# add additional directories to search for header files to IPATH
IPATH=${ROOT}/inc
IPATH+=${TIVA_ROOT}

# Include common makedefs
include ${TIVA_ROOT}/makedefs


########################################################
############### START car customization ################

# Optimizations
CFLAGS+=-O3
CFLAGS+=-Wno-pedantic

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
	python3 gen_secret.py --car-id ${CAR_ID} --secrets-dir ${SECRETS_DIR} --header-file inc/secrets.h

################ END car customization ################
#######################################################


# this rule must come first in `car`
car: ${COMPILER}
car: car_arg_check
car: gen_secret

################ start sweet-b inclusion ################
DO_MAKE_SWEET_B=yes
ifdef DO_MAKE_SWEET_B

# path to sweet-b library
SBPATH=${ROOT}/lib/sweet-b

# add path to sweet-b source files to source path
VPATH+=${SBPATH}/src
VPATH+=${SBPATH}/include

# add sweet-b library to includes path
IPATH+=${SBPATH}/include
IPATH+=${SBPATH}/src

# add compiler flag to allow sweet-b to work on Cortex-M4
CFLAGS+=-DSB_WORD_SIZE=2

# disable the unused curve
CFLAGS+=-DSB_SW_SECP256K1_SUPPORT=0

# optimizations
CFLAGS+=-DSB_UNROLL=3

# add sweet-b object files to includes path
LDFLAGS+=${COMPILER}/sb_sha256.o
LDFLAGS+=${COMPILER}/sb_fe.o
LDFLAGS+=${COMPILER}/sb_hmac_sha256.o
LDFLAGS+=${COMPILER}/sb_hmac_drbg.o
LDFLAGS+=${COMPILER}/sb_hkdf.o
LDFLAGS+=${COMPILER}/sb_sw_lib.o

# add rules to build sweet-b components
car: ${COMPILER}/sb_sha256.o
car: ${COMPILER}/sb_fe.o
car: ${COMPILER}/sb_hmac_sha256.o
car: ${COMPILER}/sb_hmac_drbg.o
car: ${COMPILER}/sb_hkdf.o
car: ${COMPILER}/sb_sw_lib.o

endif
################# end sweet-b inclusion #################

# these must be the last build rules of `car`
car: ${COMPILER}/firmware.axf
car: copy_artifacts


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
${COMPILER}/firmware.axf: ${TIVA_ROOT}/driverlib/${COMPILER}/libdriver.a

copy_artifacts:
	cp ${COMPILER}/firmware.bin ${BIN_PATH}
	cp ${COMPILER}/firmware.axf ${ELF_PATH}
	cp ${SECRETS_DIR}/car_${CAR_ID}_eeprom ${EEPROM_PATH}

SCATTERgcc_firmware=${TIVA_ROOT}/firmware.ld
ENTRY_firmware=Firmware_Startup

# Include the automatically generated dependency files.
ifneq (${MAKECMDGOALS},clean)
-include ${wildcard ${COMPILER}/*.d} __dummy__
endif