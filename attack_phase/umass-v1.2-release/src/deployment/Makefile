#  2023 eCTF
#  Deployment Makefile
#  Kyle Scaplen
#
#  (c) 2023 The MITRE Corporation
#
# This source file is part of an example system for MITRE's 2023 Embedded System CTF (eCTF).
# This code is being provided only for educational purposes for the 2023 MITRE eCTF competition,
# and may not meet MITRE standards for quality. Use this code at your own risk!

# function to check required arguments
check_defined = \
	$(strip $(foreach 1,$1, \
		$(call __check_defined,$1)))
__check_defined = \
	$(if $(value $1),, \
		$(error Undefined $1))

.PHONY: all

all:
	$(call check_defined SECRETS_DIR)
	rm -rf ${SECRETS_DIR}/tivaware && cp -r tivaware ${SECRETS_DIR}/tivaware
	rm -rf ${SECRETS_DIR}/ectf-2023-umass-rustlib && cp -r ectf-2023-umass-rustlib ${SECRETS_DIR}/ectf-2023-umass-rustlib
	rm -rf ${SECRETS_DIR}/precompute_scram_keys && cp -r precompute_scram_keys ${SECRETS_DIR}/precompute_scram_keys
	make -C ${SECRETS_DIR}/tivaware clean
	cd ${SECRETS_DIR}/ectf-2023-umass-rustlib && . ~/.cargo/env && cargo clean
	cd ${SECRETS_DIR}/precompute_scram_keys && . ~/.cargo/env && cargo clean
	head --bytes=32 /dev/urandom > ${SECRETS_DIR}/car_start_base.bin
	head --bytes=32 /dev/urandom > ${SECRETS_DIR}/unpaired_auth_base.bin
	python3 gen_package_key_tool
