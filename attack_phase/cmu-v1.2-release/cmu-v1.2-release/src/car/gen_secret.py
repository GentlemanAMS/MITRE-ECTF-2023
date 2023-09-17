#!/usr/bin/python3 -u

# @file gen_secret
# @author Jake Grycel
# @brief Example script to generate header containing secrets for the car
# @date 2023
#
# This source file is part of an example system for MITRE's 2023 Embedded CTF (eCTF).
# This code is being provided only for educational purposes for the 2023 MITRE eCTF
# competition,and may not meet MITRE standards for quality. Use this code at your
# own risk!
#
# @copyright Copyright (c) 2023 The MITRE Corporation

import sys
sys.path.append("./common/scripts/")

from header_parser import parse_header

import json
import argparse
from pathlib import Path
import struct
import monocypher
import secrets as ss
import base64

# secret file format:
# {
#   "EEPROM_DEPLOYMENT_SIGNATURE_PUBLIC_KEY": 'base64_key',
#   ...
#   "EEPROM_CAR_ENCRYPTION_PRIVATE_KEY": 'base64_key',
#   ...
#   ...
# }

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--car-id", type=int, required=True)
    parser.add_argument("--secret-file", type=Path, required=True)
    parser.add_argument("--eeprom-file", type=Path, required=True)
    args = parser.parse_args()

    # Open the secret file if it exists
    if args.secret_file.exists():
        with open(args.secret_file, "r") as fp:
            secrets = json.load(fp)
    else:
        secrets = {}

    eeprom_locations = parse_header('./inc/eeprom.h')

    # Generate car key pairs and paired fob key pairs
    car_encryption_private, car_encryption_public = monocypher.generate_key_exchange_key_pair()
    car_signature_private, car_signature_public = monocypher.generate_signing_key_pair()
    pf_encryption_private, pf_encryption_public = monocypher.generate_key_exchange_key_pair()
    pf_signature_private, pf_signature_public = monocypher.generate_signing_key_pair()

    # Add these keys to secret
    secrets['EEPROM_CAR_ENCRYPTION_PRIVATE_KEY']        = base64.b64encode(car_encryption_private).decode('ascii')
    secrets['EEPROM_CAR_SIGNATURE_PRIVATE_KEY']         = base64.b64encode(car_signature_private).decode('ascii')
    secrets['EEPROM_CAR_ENCRYPTION_PUBLIC_KEY']         = base64.b64encode(car_encryption_public).decode('ascii')
    secrets['EEPROM_CAR_SIGNATURE_PUBLIC_KEY']          = base64.b64encode(car_signature_public).decode('ascii')
    secrets['EEPROM_PAIRED_FOB_ENCRYPTION_PRIVATE_KEY'] = base64.b64encode(pf_encryption_private).decode('ascii')
    secrets['EEPROM_PAIRED_FOB_SIGNATURE_PRIVATE_KEY']  = base64.b64encode(pf_signature_private).decode('ascii')
    secrets['EEPROM_PAIRED_FOB_ENCRYPTION_PUBLIC_KEY']  = base64.b64encode(pf_encryption_public).decode('ascii')
    secrets['EEPROM_PAIRED_FOB_SIGNATURE_PUBLIC_KEY']   = base64.b64encode(pf_signature_public).decode('ascii')

    # Save the secret file
    with open(args.secret_file, "w") as fp:
        json.dump(secrets, fp, indent=4)

    eeprom_file = [0] * 2048   # retain the last 0x100 bytes (unlock/feature messages)

    # ---------------------------
    # Write car ID and Nonce seed
    # ---------------------------

    car_id_offset = eeprom_locations['EEPROM_CAR_ID']
    car_id_bytes = struct.pack('<i', args.car_id)
    eeprom_file[car_id_offset:car_id_offset + 4] = car_id_bytes

    nonce_seed_offset = eeprom_locations['EEPROM_NONCE_SEED']
    nonce_seed_bytes = struct.pack('<I', ss.randbits(32))
    eeprom_file[nonce_seed_offset:nonce_seed_offset + 4] = nonce_seed_bytes

    # ----------
    # Write keys
    # ----------

    car_encryption_private_offset = eeprom_locations['EEPROM_CAR_ENCRYPTION_PRIVATE_KEY']
    eeprom_file[car_encryption_private_offset:car_encryption_private_offset + 32] = car_encryption_private

    car_signature_private_offset = eeprom_locations['EEPROM_CAR_SIGNATURE_PRIVATE_KEY']
    eeprom_file[car_signature_private_offset:car_signature_private_offset + 32] = car_signature_private

    pf_encryption_public_offset = eeprom_locations['EEPROM_PAIRED_FOB_ENCRYPTION_PUBLIC_KEY']
    eeprom_file[pf_encryption_public_offset:pf_encryption_public_offset + 32] = pf_encryption_public

    pf_signature_public_offset = eeprom_locations['EEPROM_PAIRED_FOB_SIGNATURE_PUBLIC_KEY']
    eeprom_file[pf_signature_public_offset:pf_signature_public_offset + 32] = pf_signature_public

    depl_signature_public_offset = eeprom_locations['EEPROM_DEPLOYMENT_SIGNATURE_PUBLIC_KEY']
    depl_signature_public = base64.b64decode(secrets['EEPROM_DEPLOYMENT_SIGNATURE_PUBLIC_KEY'])
    eeprom_file[depl_signature_public_offset:depl_signature_public_offset + 32] = depl_signature_public

    # --------------------
    # Write random padding
    # --------------------

    rng_seed_size = eeprom_locations['EEPROM_RNG_SEED_SIZE']
    rng_seed_offset = eeprom_locations['EEPROM_RNG_SEED']

    rng_seed_bytes = ss.token_bytes(rng_seed_size)
    eeprom_file[rng_seed_offset:rng_seed_offset+rng_seed_size] = rng_seed_bytes

    # ------------------
    # Save EEPROM binary
    # ------------------

    assert(len(eeprom_file))
    with open(args.eeprom_file, "wb") as fp:
        fp.write(bytes(eeprom_file))

if __name__ == "__main__":
    main()
