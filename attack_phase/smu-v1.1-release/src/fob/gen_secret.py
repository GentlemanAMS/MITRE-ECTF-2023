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


# Return a string in a format that C header file understands
def format_bytes(byte_string) -> str:
    return "".join("\\x{:02x}".format(b) for b in byte_string)


def parse_secrets(raw_secrets) -> dict:
    parsed_secrets = {}
    for k, v in raw_secrets.items():
        parsed_secrets[k] = format_bytes(bytes.fromhex(v))
    return parsed_secrets


def get_ca_pk(secret_dir) -> str:
    with open(f"{secret_dir}/ca_kp.json", "r") as fp:
        ca_kp = json.load(fp)
        ca_kp = parse_secrets(ca_kp)
        return ca_kp["pk"]


def get_unpaired_fob_kp(secret_dir) -> dict:
    with open(f"{secret_dir}/unpaired_fob.json", "r") as fp:
        fob_kp = json.load(fp)
        fob_kp = parse_secrets(fob_kp)
        return fob_kp


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--car-id", type=int)
    parser.add_argument("--pair-pin", type=str)
    parser.add_argument("--secret-file", type=str)
    parser.add_argument("--secret-dir", type=Path, required=True)
    parser.add_argument("--header-file", type=Path, required=True)
    parser.add_argument("--paired", action="store_true")
    args = parser.parse_args()

    ca_pk = get_ca_pk(args.secret_dir)

    print("Retrieving unpaired fob secrets")
    ufob_kp = get_unpaired_fob_kp(args.secret_dir)
    ufob_pk = ufob_kp["pk"]
    ufob_sk = ufob_kp["sk"]

    if args.paired:
        # Open the secret file, get the carfob's secret
        car_secret_file_name = Path(f"{args.secret_dir}/{args.secret_file}")

        if not car_secret_file_name.exists():
            print("ERROR: Car secret file does not exist")
            exit(1)

        # Retrieve car-fob shared link key
        with open(car_secret_file_name, "r") as fp:
            secrets = json.load(fp)
            carfob_secret = secrets[str(args.car_id)]
            carfob_secret = parse_secrets(carfob_secret)
            car_link_secret = carfob_secret["link_key"]
            fob_pk = carfob_secret["fob_pk"]
            fob_sk = carfob_secret["fob_sk"]
            fob_sig = carfob_secret["signature"]

        # Write to header file
        with open(args.header_file, "w") as fp:
            fp.write("#ifndef __FOB_SECRETS__\n")
            fp.write("#define __FOB_SECRETS__\n\n")
            fp.write("#define PAIRED 1\n")
            fp.write(f'#define PAIR_PIN "{args.pair_pin}"\n')
            fp.write(f'#define CAR_ID "{args.car_id}"\n')
            fp.write(f'#define CAR_SECRET "{car_link_secret}"\n')
            fp.write(f'#define CA_PK "{ca_pk}"\n')
            fp.write(f'#define UNPAIRED_FOB_PK "{ufob_pk}"\n')
            fp.write(f'#define UNPAIRED_FOB_SK "0"\n\n')
            fp.write(f'#define PAIRED_FOB_PK "{fob_pk}"\n')
            fp.write(f'#define PAIRED_FOB_SK "{fob_sk}"\n')
            fp.write(f'#define PAIRED_FOB_SIG "{fob_sig}"\n\n')
            fp.write("#endif\n")
    else:
        # Write to header file
        with open(args.header_file, "w") as fp:
            fp.write("#ifndef __FOB_SECRETS__\n")
            fp.write("#define __FOB_SECRETS__\n\n")
            fp.write("#define PAIRED 0\n")
            fp.write('#define PAIR_PIN "000000"\n')
            fp.write('#define CAR_ID "000000"\n')
            fp.write('#define CAR_SECRET "000000"\n')
            fp.write(f'#define CA_PK "{ca_pk}"\n')
            fp.write(f'#define UNPAIRED_FOB_PK "{ufob_pk}"\n')
            fp.write(f'#define UNPAIRED_FOB_SK "{ufob_sk}"\n\n')
            fp.write(f'#define PAIRED_FOB_PK "0"\n')
            fp.write(f'#define PAIRED_FOB_SK "0"\n')
            fp.write(f'#define PAIRED_FOB_SIG "0"\n\n')
            fp.write("#endif\n")


if __name__ == "__main__":
    main()
