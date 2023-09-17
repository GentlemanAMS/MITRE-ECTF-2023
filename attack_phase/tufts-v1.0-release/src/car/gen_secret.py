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

import json
import argparse
import secrets as scrs
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--car-id", type=int, required=True)
    parser.add_argument("--secret-file", type=Path, required=True)
    parser.add_argument("--header-file", type=Path, required=True)
    args = parser.parse_args()

    # Open the secret file if it exists
    if args.secret_file.exists():
        with open(args.secret_file, "r") as fp:
            secrets = json.load(fp)
    else:
        secrets = {}

    #Key generation    
    car_pass = scrs.randbits(128)
    car_pass_bytes = car_pass.to_bytes((car_pass.bit_length() + 7) // 8, byteorder='big')
    car_pass_hex = ''.join([f"\\x{byte:02x}" for byte in car_pass_bytes])
    
    car_secret = scrs.randbits(128)
    car_secret_bytes = car_secret.to_bytes((car_secret.bit_length() + 7) // 8, byteorder='big')
    car_secret_hex = ''.join([f"\\x{byte:02x}" for byte in car_secret_bytes])
    
    #JSON dictionary
    car_secrets = {}
    car_secrets["SECRET"] = car_secret
    car_secrets["PASS"] = car_pass
    secrets[str(args.car_id)] = car_secrets

    # Save the secret file
    with open(args.secret_file, "w") as fp:
        json.dump(secrets, fp, indent=4)

    # Write to header file
    with open(args.header_file, "w") as fp:
        fp.write("#ifndef __CAR_SECRETS__\n")
        fp.write("#define __CAR_SECRETS__\n\n")
        fp.write(f'#define CAR_SECRET "{car_secret_hex}"\n\n')
        fp.write(f'#define CAR_ID "{args.car_id}"\n\n')
        fp.write(f'#define PASSWORD "{car_pass_hex}"\n\n')
        fp.write("#endif\n")


if __name__ == "__main__":
    main()