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
from pathlib import Path
from monocypher import (
    generate_signing_key_pair,
    generate_key,
    signature_sign,
    signature_check,
)


# Return a string in a format that C header file understands
def format_bytes(byte_string) -> str:
    return "".join("\\x" "{:02x}".format(b) for b in byte_string)


def generate_paired_fob_kp() -> dict:
    sk, pk = generate_signing_key_pair()
    kp = {"pk": pk, "sk": sk}
    return kp


# Sign the public key with the global private key and return the CA pk and signature
def sign_pk(secret_dir, pk) -> tuple[bytes, bytes]:
    with open(f"{secret_dir}/ca_kp.json", "r") as fp:
        ca_kp = json.load(fp)
        ca_sk = bytes.fromhex(ca_kp["sk"])
        ca_pk = bytes.fromhex(ca_kp["pk"])
        sig = signature_sign(ca_sk, pk)
        assert signature_check(sig, ca_pk, pk)

    return sig, ca_pk


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--car-id", type=int, required=True)
    parser.add_argument("--secret-dir", type=Path, required=True)
    parser.add_argument("--secret-file", type=str, required=True)
    parser.add_argument("--header-file", type=Path, required=True)
    args = parser.parse_args()

    # Open the secret file if it exists
    car_secret_file_name = Path(f"{args.secret_dir}/{args.secret_file}")
    if car_secret_file_name.exists():
        print("Secret file exists, loading...")
        with open(car_secret_file_name, "r") as fp:
            carfob_secrets = json.load(fp)
    else:
        print("Secret file does not exist, creating later...")
        carfob_secrets = {}

    print("Generating car-fob link key...")
    # Create the car-fob link key (symmetric)
    carfob_link_key = generate_key(length=32)

    print("Generating Paired Fob keys")
    # Generate paired fob key-pair for Signing Purposes
    fob_keypair = generate_paired_fob_kp()

    print("Signing paired fob public key")
    # Sign the fob public-key with the CA private-key
    sig, ca_pk = sign_pk(args.secret_dir, fob_keypair["pk"])

    carfob_secret = {
        "link_key": carfob_link_key.hex(),
        "fob_pk": fob_keypair["pk"].hex(),
        "fob_sk": fob_keypair["sk"].hex(),
        "signature": sig.hex(),
    }

    # Store the new secrets even if a previous one has already been generated
    carfob_secrets[str(args.car_id)] = carfob_secret

    # Save the secret file
    print("Saving secrets to file.")
    with open(car_secret_file_name, "w") as fp:
        json.dump(carfob_secrets, fp, indent=4)

    # Parse the carfob_link_key and ca_pk into standardised format
    car_link_secret = format_bytes(carfob_link_key)
    ca_pk = format_bytes(ca_pk)

    # Write to header file
    with open(args.header_file, "w") as fp:
        fp.write("#ifndef __CAR_SECRETS__\n")
        fp.write("#define __CAR_SECRETS__\n\n")
        fp.write(f'#define CAR_SECRET "{car_link_secret}"\n')
        fp.write(f'#define CA_PK "{ca_pk}"\n')
        fp.write(f'#define CAR_ID "{args.car_id}"\n\n')
        fp.write("#endif\n")


if __name__ == "__main__":
    main()
