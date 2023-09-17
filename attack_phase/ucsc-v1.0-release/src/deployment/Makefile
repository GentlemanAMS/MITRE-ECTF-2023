deployment: FORCE
	head -c 32 /dev/random > ${SECRETS_DIR}/FEATURE_SIGNING_KEY
	head -c 32 /dev/random > ${SECRETS_DIR}/PAIRING_MANUFACTURER_PAIRED_FOB_SIGNING_KEY
	head -c 32 /dev/random > ${SECRETS_DIR}/PAIRING_MANUFACTURER_UNPAIRED_FOB_SIGNING_KEY
#	Create the verifying key files, since the verifying keys are shorter than the field bounds.
	head -c 128 /dev/zero > ${SECRETS_DIR}/FEATURE_VERIFYING_KEY
	head -c 128 /dev/zero > ${SECRETS_DIR}/PAIRING_MANUFACTURER_PAIRED_FOB_VERIFYING_KEY
	head -c 128 /dev/zero > ${SECRETS_DIR}/PAIRING_MANUFACTURER_UNPAIRED_FOB_VERIFYING_KEY

FORCE:;
