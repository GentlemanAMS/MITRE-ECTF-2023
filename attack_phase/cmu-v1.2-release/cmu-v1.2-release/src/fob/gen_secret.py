#!/usr/bin/python3 -u

# @file gen_secret
# @author Jake Grycel
# @brief Example script to generate header containing secrets for the fob
# @date 2023
#
# This source file is part of an example system for MITRE's 2023 Embedded CTF (eCTF).
# This code is being provided only for educational purposes for the 2023 MITRE eCTF
# competition, and may not meet MITRE standards for quality. Use this code at your
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
import base64
import secrets as ss

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--car-id", type=int)
    parser.add_argument("--pair-pin", type=str)
    parser.add_argument("--secret-file", type=Path)
    parser.add_argument("--eeprom-file", type=Path)
    parser.add_argument("--paired", action="store_true")
    args = parser.parse_args()

    if args.paired:
        with open(args.secret_file, "r") as fp:
            secrets = json.load(fp)

        eeprom_file = [0] * 2048

        eeprom_locations = parse_header('./inc/eeprom.h')

        # -----------------------------
        # Write paired state and car ID
        # -----------------------------

        is_paired_offset = eeprom_locations['EEPROM_IS_PAIRED_FOB']
        eeprom_file[is_paired_offset] = 1

        car_id_offset = eeprom_locations['EEPROM_CAR_ID']
        car_id_bytes = struct.pack('<i', args.car_id)
        eeprom_file[car_id_offset:car_id_offset + 4] = car_id_bytes

        feature_bitvec_offset = eeprom_locations['EEPROM_FEATURE_BITVEC']
        eeprom_file[feature_bitvec_offset:feature_bitvec_offset+4] = struct.pack('<i', 0)

        # ---------------
        # Write key pairs
        # ---------------

        pf_encryption_private_offset = eeprom_locations['EEPROM_PAIRED_FOB_ENCRYPTION_PRIVATE_KEY']
        pf_encryption_private = base64.b64decode(secrets['EEPROM_PAIRED_FOB_ENCRYPTION_PRIVATE_KEY'])
        eeprom_file[pf_encryption_private_offset:pf_encryption_private_offset + 32] = pf_encryption_private

        pf_signature_private_offset = eeprom_locations['EEPROM_PAIRED_FOB_SIGNATURE_PRIVATE_KEY']
        pf_signature_private = base64.b64decode(secrets['EEPROM_PAIRED_FOB_SIGNATURE_PRIVATE_KEY'])
        eeprom_file[pf_signature_private_offset:pf_signature_private_offset + 32] = pf_signature_private

        car_encryption_public_offset = eeprom_locations['EEPROM_CAR_ENCRYPTION_PUBLIC_KEY']
        car_encryption_public = base64.b64decode(secrets['EEPROM_CAR_ENCRYPTION_PUBLIC_KEY'])
        eeprom_file[car_encryption_public_offset:car_encryption_public_offset + 32] = car_encryption_public

        car_signature_public_offset = eeprom_locations['EEPROM_CAR_SIGNATURE_PUBLIC_KEY']
        car_signature_public = base64.b64decode(secrets['EEPROM_CAR_SIGNATURE_PUBLIC_KEY'])
        eeprom_file[car_signature_public_offset:car_signature_public_offset + 32] = car_signature_public

        depl_signature_public_offset = eeprom_locations['EEPROM_DEPLOYMENT_SIGNATURE_PUBLIC_KEY']
        depl_signature_public = base64.b64decode(secrets['EEPROM_DEPLOYMENT_SIGNATURE_PUBLIC_KEY'])
        eeprom_file[depl_signature_public_offset:depl_signature_public_offset + 32] = depl_signature_public

        upf_encryption_public_offset = eeprom_locations['EEPROM_UNPAIRED_FOB_ENCRYPTION_PUBLIC_KEY']
        upf_encryption_public = base64.b64decode(secrets['EEPROM_UNPAIRED_FOB_ENCRYPTION_PUBLIC_KEY'])
        eeprom_file[upf_encryption_public_offset:upf_encryption_public_offset + 32] = upf_encryption_public

        # -----------------------------------
        # Write keyed hash of PIN and the key
        # -----------------------------------

        pin_hash_key = ss.token_bytes(64)   # 64 byte random key for hashing

        pin_hash_offset = eeprom_locations['EEPROM_CAR_PIN_HASH']
        pin_hash_key_offset = eeprom_locations['EEPROM_CAR_PIN_HASH_KEY']

        assert (len(args.pair_pin) == 6)
        # uppercase pin and keyed hash
        pin_hash = monocypher.blake2b(args.pair_pin.upper(), key=pin_hash_key)
        assert (len(pin_hash) == 64)
        eeprom_file[pin_hash_offset:pin_hash_offset + 64] = pin_hash
        eeprom_file[pin_hash_key_offset:pin_hash_key_offset + 64] = pin_hash_key

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

    else:
        with open(args.secret_file, "r") as fp:
            secrets = json.load(fp)

        eeprom_file = [0] * 2048

        eeprom_locations = parse_header('./inc/eeprom.h')

        # ------------------
        # Write paired state
        # ------------------

        is_paired_offset = eeprom_locations['EEPROM_IS_PAIRED_FOB']
        eeprom_file[is_paired_offset] = 0

        # -------------------------------------
        # Write upf encryption private key pair
        # -------------------------------------

        upf_encryption_private_offset = eeprom_locations['EEPROM_UNPAIRED_FOB_ENCRYPTION_PRIVATE_KEY']
        upf_encryption_private = base64.b64decode(secrets['EEPROM_UNPAIRED_FOB_ENCRYPTION_PRIVATE_KEY'])
        eeprom_file[upf_encryption_private_offset:upf_encryption_private_offset + 32] = upf_encryption_private

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
