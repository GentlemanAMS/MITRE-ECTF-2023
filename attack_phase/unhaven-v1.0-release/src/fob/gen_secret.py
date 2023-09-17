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

import json
import argparse
from pathlib import Path
import hashlib 
from Crypto.Cipher import AES

def bytearray_to_cstring(in_b: bytearray) -> str:
    st = "{"
    for c in in_b:
        st += f"{c:d},"
    st = st[:-1] + "}"

    return st

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--car-id", type=int)
    parser.add_argument("--pair-pin", type=str)
    parser.add_argument("--secret-file", type=Path)
    parser.add_argument("--header-file", type=Path)
    parser.add_argument("--paired", action="store_true")
    args = parser.parse_args()

    if args.paired:
        # Open the secret file, get the car's secret
        with open(args.secret_file, "r") as fp:
            secrets_dict = json.load(fp)
            car_secret = secrets_dict[str(args.car_id)+"_secret_ccode"]
            pin_encrypt = bytearray(secrets_dict["pin_encrypt_key"])

        hash_pin = hashlib.blake2s(args.pair_pin.encode('utf-8'), digest_size=16).digest()
        aes_cipher = AES.new(pin_encrypt, AES.MODE_ECB)
        encrypted_pin = aes_cipher.encrypt(hash_pin)

        encrypted_pin_ccode = bytearray_to_cstring(encrypted_pin)

        # Write to header file
        with open(args.header_file, "w") as fp:
            fp.write("#ifndef __FOB_SECRETS__\n")
            fp.write("#define __FOB_SECRETS__\n\n")
            fp.write("#define PAIRED 1\n")
            fp.write(f'#define PAIR_PIN {encrypted_pin_ccode}\n')
            fp.write(f'#define CAR_ID {args.car_id}\n')
            # NOTE: This car secret is already in a nice string format
            fp.write(f'#define CAR_SECRET {car_secret}\n\n')
            fp.write("#endif\n")
    else:
        # Write to header file
        with open(args.header_file, "w") as fp:
            fp.write("#ifndef __FOB_SECRETS__\n")
            fp.write("#define __FOB_SECRETS__\n\n")
            fp.write("#define PAIRED 0\n")
            fp.write('#define PAIR_PIN {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}\n')
            fp.write('#define CAR_ID "000000"\n')
            fp.write('#define CAR_SECRET "000000"\n\n')
            fp.write("#endif\n")


if __name__ == "__main__":
    main()
