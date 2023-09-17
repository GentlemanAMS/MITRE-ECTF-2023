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

import json
import argparse
from pathlib import Path
import hashlib
import struct
import monocypher
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
    parser.add_argument("--secret-file", type=Path, required=True)
    args = parser.parse_args()

    secrets = {}

    # Generate deployment and unpaired fob key pairs
    depl_signature_private, depl_signature_public = monocypher.generate_signing_key_pair()
    upf_encryption_private, upf_encryption_public = monocypher.generate_key_exchange_key_pair()

    # Add these keys to secret
    secrets['EEPROM_DEPLOYMENT_SIGNATURE_PRIVATE_KEY'] = base64.b64encode(depl_signature_private).decode('ascii')
    secrets['EEPROM_DEPLOYMENT_SIGNATURE_PUBLIC_KEY'] = base64.b64encode(depl_signature_public).decode('ascii')
    secrets['EEPROM_UNPAIRED_FOB_ENCRYPTION_PRIVATE_KEY'] = base64.b64encode(upf_encryption_private).decode('ascii')
    secrets['EEPROM_UNPAIRED_FOB_ENCRYPTION_PUBLIC_KEY']  = base64.b64encode(upf_encryption_public).decode('ascii')

    # Save the secret file
    with open(args.secret_file, "w") as fp:
        json.dump(secrets, fp, indent=4)

if __name__ == "__main__":
    main()
