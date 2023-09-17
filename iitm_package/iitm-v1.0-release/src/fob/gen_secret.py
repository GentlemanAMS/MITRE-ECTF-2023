#!/usr/bin/python3 -u

# @file gen_secret
# used to generate different encryption key, passwords and seed

import json
import argparse
from pathlib import Path
import random

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--car-id", type=int)
    parser.add_argument("--pair-pin", type=str)
    parser.add_argument("--secret-file", type=Path)
    parser.add_argument("--header-file", type=Path)
    parser.add_argument("--paired", action="store_true")
    parser.add_argument("--eeprom-file", type=Path)
    args = parser.parse_args()

    random.seed()
    # write content into secret.h
    with open(args.header_file, "w") as fp:
        fp.write("#ifndef __FOB_SECRETS__\n")
        fp.write("#define __FOB_SECRETS__\n\n")

        # salt for random number 
        fp.write(f"static uint8_t random_seed_constant[4] =" + "{" + f"{random.randint(0, 255)}, {random.randint(0, 255)}, {random.randint(0, 255)}, {random.randint(0, 255)}" + "};\n\n")

        # passwords for different blocks in eeprom
        fp.write(f"static uint32_t pairedbool_password =" + f"{random.randint(0, 2147483648)}" +";\n")
        fp.write(f"static uint32_t carid_password =" + f"{random.randint(0, 2147483648)}" +";\n")
        fp.write(f"static uint32_t pairingpin_password =" + f"{random.randint(0, 2147483648)}" +";\n")
        fp.write(f"static uint32_t featureinfo_password =" + f"{random.randint(0, 2147483648)}" +";\n")
        fp.write(f"static uint32_t package_key_password =" + f"{random.randint(0, 2147483648)}" +";\n")
        fp.write(f"static uint32_t unlock_key_password =" + f"{random.randint(0, 2147483648)}" +";\n")

        fp.write("#endif\n")

    if args.paired:
        # Open the secret file, get the car's secret
        with open(str(args.secret_file) + f"/{args.car_id}.json", "r") as fp:
            car_info = json.load(fp)

        enc_key_pairs = car_info["enc_key_pairs"]
        package_enc_key = car_info["package_enc_key"]

        with open(args.eeprom_file, "wb") as fp:
            # 127 is paired bool 0b01111111
            # "." is used to pad the data
            pair_bool_bytes = chr(127).ljust(4, ".").encode()
            car_id_bytes = (chr(args.car_id)).ljust(4, ".").encode()
            pin_bytes = args.pair_pin.ljust(8, ".").encode()
            feature_bytes = (chr(0).rjust(4, ".")).encode()
            package_enc_key_bytes = package_enc_key.encode()

            fp.write(("."*64).encode())

            fp.write(pair_bool_bytes)
            fp.write(("."*60).encode())
            
            fp.write(car_id_bytes)
            fp.write(("."*60).encode())

            fp.write(pin_bytes)
            fp.write(("."*56).encode())

            fp.write(feature_bytes)
            fp.write(("."*60).encode())

            fp.write(package_enc_key_bytes)
            fp.write(("."*48).encode())

            # reverese the order of storing the key pairs
            for pair in enc_key_pairs:
                fp.write(pair[1].encode())
                fp.write(pair[0].encode())

    else:
        # Write to header file
        with open(args.eeprom_file, "wb") as fp:
            fp.write((chr(0) * 768).encode())


if __name__ == "__main__":
    main()