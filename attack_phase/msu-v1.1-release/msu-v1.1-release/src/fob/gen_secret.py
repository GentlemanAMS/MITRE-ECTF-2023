#!/usr/bin/python3 -u

# @file gen_secret
# @author Spartan State Security Team
# @brief Script to generate header containing secrets for the secure key fob device
# @date 2023
#
#  This source file is part of our designed system
#  for MITRE's 2023 Embedded System CTF (eCTF).

import json
import argparse
from pathlib import Path
import struct
import Crypto.PublicKey.ECC as ecc
from Crypto.Util.number import long_to_bytes
from Crypto.Random import get_random_bytes

ECC_PRIVSIZE = 32
ECC_SIGNATURE_SIZE = 64
YES_PAIRED = 0x20202020
NO_UPAIRED = 0xFFFFFFFF

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--car-id", type=int)
    parser.add_argument("--pair-pin", type=str)
    parser.add_argument("--secrets-dir", type=Path)
    parser.add_argument("--header-file", type=Path)
    parser.add_argument("--paired", action="store_true")
    args = parser.parse_args()

    # Set Known Values of Fob Data for EEPROM
    paired = YES_PAIRED if args.paired else NO_UPAIRED
    pin = int(args.pair_pin,16) if args.paired else NO_UPAIRED
    package_data = b"\xFF" * ECC_SIGNATURE_SIZE * 3

    # Open the secret file if it exists
    secret_file = args.secrets_dir / "car_secrets.json"
    if secret_file.exists():
        with open(secret_file, "r") as fp:
            secrets = json.load(fp)
    elif args.paired:
            raise Exception("Secrets file not found in directory, should already exist before building paired fob")
    
    # Load car private key
    if args.paired:
        car_privkey_pem = secrets[str(args.car_id)]["privkey_pem"]
        car_privkey = ecc.import_key(car_privkey_pem)
        car_privkey_bytes = long_to_bytes(car_privkey.d, ECC_PRIVSIZE)
    else:
        car_privkey_bytes = b"\xFF" * ECC_PRIVSIZE
    
    # Pack EEPROM Fob Data
    eeprom_data = struct.pack(
        f"<II{ECC_PRIVSIZE}s{ECC_SIGNATURE_SIZE*3}s",
        paired,
        pin,
        car_privkey_bytes,
        package_data
    )

    # Write EEPROM File
    eeprom_path = args.secrets_dir / "temp_eeprom"
    with open(eeprom_path, "wb") as fp:
        fp.write(eeprom_data)

    # Generate Entropy
    entropy = get_random_bytes(0x400)

    # Write Header File
    if args.paired:
        # OG_PFOB
        with open(args.header_file, "w") as fp:
            fp.write("#ifndef __FOB_SECRETS__\n")
            fp.write("#define __FOB_SECRETS__\n\n")
            fp.write('#include "firmware.h"\n')
            fp.write("#define OG_PFOB 1\n")
            fp.write("#define OG_UFOB 0\n")
            fp.write(f"const uint8_t S_ENTROPY[sizeof(ENTROPY)] = {{ {','.join(hex(b) for b in entropy)} }};\n")
            fp.write("#endif\n")
    else:
        # OG_UFOB
        with open(args.header_file, "w") as fp:
            fp.write("#ifndef __FOB_SECRETS__\n")
            fp.write("#define __FOB_SECRETS__\n\n")
            fp.write('#include "firmware.h"\n')
            fp.write("#define OG_PFOB 0\n")
            fp.write("#define OG_UFOB 1\n")
            fp.write(f"const uint8_t S_ENTROPY[sizeof(ENTROPY)] = {{ {','.join(hex(b) for b in entropy)} }};\n")
            fp.write("#endif\n")


if __name__ == "__main__":
    main()
