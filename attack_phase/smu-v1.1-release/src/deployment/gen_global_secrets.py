#!/usr/bin/python3 -u

# @file generate_secrets
# @author SMU
# @brief Generates secrets for the deployment
# @date 2023

from pathlib import Path
from monocypher import generate_signing_key_pair

import json
import argparse


def generate_sig_kp() -> dict:
    sk, pk = generate_signing_key_pair()
    kp = {"pk": pk, "sk": sk}
    return kp


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--secrets-dir", type=Path, required=True)
    args = parser.parse_args()

    # Create the directory
    args.secrets_dir.mkdir(parents=True, exist_ok=True)

    print("Generating CA keypair...")
    ca_kp = generate_sig_kp()

    print("Generating unpaired fob keypair...")
    unpaired_fob_kp = generate_sig_kp()

    unpaired_fob_secrets = {k: v.hex() for k, v in unpaired_fob_kp.items()}
    ca_kp = {k: v.hex() for k, v in ca_kp.items()}

    print("Writing secrets to files...")
    with open(f"{args.secrets_dir}/ca_kp.json", "w") as f:
        f.write(json.dumps(ca_kp))

    with open(f"{args.secrets_dir}/unpaired_fob.json", "w") as f:
        f.write(json.dumps(unpaired_fob_secrets))

    print("Done generating secrets.")


if __name__ == "__main__":
    main()
