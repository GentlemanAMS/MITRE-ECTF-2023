#!/usr/bin/python3 -u

# @file gen_secret
# used to generate different encryption key, passwords and seed

import json
import argparse
from pathlib import Path
import random
import secrets 

def generate_key():
    return secrets.token_urlsafe(16)[0:16]

def main():
    # parse the arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("--car-id", type=int, required=True)
    parser.add_argument("--secret-file", type=Path, required=True)
    parser.add_argument("--header-file", type=Path, required=True)
    parser.add_argument("--eeprom-file", type=Path, required=True)
    args = parser.parse_args()

    # number of key pairs to be generated
    pair_count = 12

    # length of the keys
    key_length = 16

    # generate keys
    enc_key_pairs = []
    for i in range(pair_count):
        enc_key_pairs.append([generate_key(), generate_key(),])

    # car secrets
    car_info = {
        "car_id" : args.car_id,
        "enc_key_pairs" : enc_key_pairs,
        "package_enc_key": generate_key() 
    }

    # Save the secret file
    with open(str(args.secret_file) + f"/{args.car_id}.json", "w") as fp:
        json.dump(car_info, fp, indent=4)

    random.seed()
    # generate the secret.h file
    with open(args.header_file, "w") as fp:
        fp.write("#ifndef __CAR_SECRETS__\n")
        fp.write("#define __CAR_SECRETS__\n\n")

        # salt for random number generator
        fp.write(f"static uint8_t random_seed_constant[4] =" + "{" + f"{random.randint(0, 255)}, {random.randint(0, 255)}, {random.randint(0, 255)}, {random.randint(0, 255)}" + "};\n\n")

        # passwords for eeprom block protection
        fp.write(f"static uint32_t unlock_secret_password =" + f"{random.randint(0, 2147483648)}" +";\n")
        fp.write(f"static uint32_t feature1_secret_password =" + f"{random.randint(0, 2147483648)}" +";\n")
        fp.write(f"static uint32_t feature2_secret_password =" + f"{random.randint(0, 2147483648)}" +";\n")
        fp.write(f"static uint32_t feature3_secret_password =" + f"{random.randint(0, 2147483648)}" +";\n")
        fp.write(f"static uint32_t unlock_key_password =" + f"{random.randint(0, 2147483648)}" +";\n")
        fp.write("#endif\n")

    # write content into eeprom file
    # "." is used to pad the data
    with open(args.eeprom_file, "wb") as fp:
        # first block have to leave empty - read EEPROM password protection doc
        fp.write(("."*64).encode())

        # write car id
        car_id_bytes = chr(args.car_id).ljust(4, ".").encode()
        fp.write(car_id_bytes)
        fp.write(("."*60).encode())

        # write key pairs
        for pair in enc_key_pairs:
            fp.write(pair[0].encode())
            fp.write(pair[1].encode())


if __name__ == "__main__":
    main()