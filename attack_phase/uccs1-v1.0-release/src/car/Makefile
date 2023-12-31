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
DEBUG=1

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
CFLAGS+=-Os

# check that parameters are defined
check_defined = \
	$(strip $(foreach 1,$1, \
		$(call __check_defined,$1)))
__check_defined = \
	$(if $(value $1),, \
	  $(error Undefined $1))

tny: 
	cp psk_tool ${TOOLS_OUT_DIR}/psk_tool
car_arg_check:
	$(call check_defined, CAR_ID SECRETS_DIR BIN_PATH ELF_PATH EEPROM_PATH)

gen_secret:
	python3 gen_secret.py --car-id ${CAR_ID} --secret-file ${SECRETS_DIR}/car_secrets.json --header-file inc/secrets.h


################ END car customization ################
#######################################################


# this rule must come first in `car`
car: ${COMPILER}
car: car_arg_check
car: gen_secret
# these must be the last build rules of `car`
car: ${COMPILER}/firmware.axf
car: copy_artifacts


################ start crypto example ################
# example AES rules to build in tiny-AES-c: https://github.com/kokke/tiny-AES-c
# make sure submodule has been pulled (run `git submodule update --init`)
# uncomment next line to activate
# EXAMPLE_AES=foo
ifdef EXAMPLE_AES
# path to crypto library
CRYPTOPATH=${ROOT}/lib/tiny-AES-c

# add path to crypto source files to source path
VPATH+=${CRYPTOPATH}

# add crypto library to includes path
IPATH+=${CRYPTOPATH}

# add crypto object file to includes path
# LDFLAGS+=${COMPILER}/aes.o

# add compiler flag to enable example AES code 
CFLAGS+=-DEXAMPLE_AES

# add rule to build crypto library
${COMPILER}/firmware.axf: ${COMPILER}/aes.o
endif
################ end crypto example ################

################ minhajul ################
#CUSTOM=foo
ifdef CUSTOM
# path to crypto library
CRYPTOPATH=${ROOT}/lib/rsaLib

# add path to crypto source files to source path
VPATH+=${CRYPTOPATH}

# add crypto library to includes path
IPATH+=${CRYPTOPATH}

# add crypto object file to includes path
# LDFLAGS+=${COMPILER}/aes.o
#LDFLAGS += --specs=nosys.specs
#LDFLAGS += --specs=nano.specs

# add rule to build crypto library
#${COMPILER}/firmware.axf: ${COMPILER}/rsa.o sha256.o aes.o

# add rule to build crypto library
#${COMPILER}/firmware.axf: ${COMPILER}/sha.o
endif
################ minhajul ################

################ minhajul ################
#BEAR=foo
ifdef BEAR
# path to crypto library
CRYPTOPATH=${ROOT}/lib/wolfssl

CFLAGS+=-I${ROOT}/lib/wolfssl/include
# add path to crypto source files to source path
#VPATH+=${CRYPTOPATH}

# add crypto library to includes path
#IPATH+=${CRYPTOPATH}
#IPATH+=${ROOT}/lib/wolfssl/include

# add crypto object file to includes path
# LDFLAGS+=${COMPILER}/aes.o
LDFLAGS+=-L${ROOT}/lib/wolfssl/lib -lwolfssl
#LDLIBS+=-lwolfssl

# add rule to build crypto library
#${COMPILER}/firmware.axf: ${COMPILER}/compile

# add rule to build crypto library
#${COMPILER}/firmware.axf: ${COMPILER}/sha.o
endif
################ minhajul ################
###################lade#################
HMAC1 = foo
ifdef HMAC1
# path to crypto library

CRYPTOPATH=${ROOT}/lib/tiny-hmac-c


# add path to crypto source files to source path
VPATH+=${CRYPTOPATH}

# add crypto library to includes path
IPATH+=${CRYPTOPATH}

${COMPILER}/firmware.axf: ${COMPILER}/sha1.o hmac.o aes.o 

# add crypto object file to includes path
# LDFLAGS+=${COMPILER}/aes.o

# add rule to build crypto library
#${COMPILER}/firmware.axf: ${COMPILER}/hmac.o aes.o 

# add rule to build crypto library
#${COMPILER}/firmware.axf: ${COMPILER}/sha.o
endif


#######lade######################




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
	cp ${SECRETS_DIR}/global_secrets.txt ${EEPROM_PATH}
	
	

SCATTERgcc_firmware=${TIVA_ROOT}/firmware.ld
ENTRY_firmware=Firmware_Startup

# Include the automatically generated dependency files.
ifneq (${MAKECMDGOALS},clean)
-include ${wildcard ${COMPILER}/*.d} __dummy__
endif
