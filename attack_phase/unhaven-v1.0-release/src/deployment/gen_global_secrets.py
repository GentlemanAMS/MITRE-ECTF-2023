#!/usr/bin/python3 -u

import secrets
import json
import argparse
from pathlib import Path


def bytearray_to_cstring(in_b: bytearray) -> str:
    st = "{"
    for c in in_b:
        st += f"{c:d},"
    st = st[:-1] + "}"

    return st


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--secret-file", type=Path, required=True)
    parser.add_argument("--eeprom-file", type=Path, required=True)
    args = parser.parse_args()

    # Open the secret file if it exists
    if args.secret_file.exists():
        with open(args.secret_file, "r") as fp:
            secrets_dict = json.load(fp)
    else:
        secrets_dict = {}

    feature_unlock = secrets.token_bytes(24)
    secrets_dict["feature_unlock_key"] = list(feature_unlock)

    feature_unlock_iv = secrets.token_bytes(16)
    secrets_dict["feature_unlock_key_iv"] = list(feature_unlock_iv)

    pin_encrypted_secret = secrets.token_bytes(24)
    secrets_dict["pin_encrypt_key"] = list(pin_encrypted_secret)

    # Write to a JSON file so that we can read it later
    with open(args.secret_file, "w") as fp:
        json.dump(secrets_dict, fp, indent=4)

    with open(args.eeprom_file, "wb") as fp:
        fp.write(feature_unlock)
        fp.write(bytearray(32-24))      # Zero padding
        fp.write(feature_unlock_iv)
        fp.write(bytearray(32-16))      # Zero padding
        fp.write(pin_encrypted_secret)
        fp.write(bytearray(32-24))      # Zero padding


if __name__ == "__main__":
    main()