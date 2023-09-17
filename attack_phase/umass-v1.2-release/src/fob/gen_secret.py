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
import struct
import argparse
from pathlib import Path

import hmac
import base64
from os import urandom, environ
import subprocess

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--car-id", type=int, default=0xFFFFFFFF)
    parser.add_argument("--car-start-base", type=Path, required=True)
    parser.add_argument("--unpaired-auth-base", type=Path, required=True)
    parser.add_argument("--pair-pin", type=str)
    #parser.add_argument("--secret-file", type=Path)
    parser.add_argument("--header-file", type=Path, required=True)
    parser.add_argument("--eeprom-file", type=Path, required=True)
    #parser.add_argument("--paired", action="store_true")
    args = parser.parse_args()

    with open(args.car_start_base, "rb") as fp:
        car_start_base = fp.read()
    with open(args.unpaired_auth_base, "rb") as fp:
        unpaired_auth_base = fp.read()

    car_id_bytes = struct.pack('<I', args.car_id)

    eeprom_bytearr = bytearray([0xff]*0xa0)
    eeprom_bytearr[0x00:0x04] = car_id_bytes
    #eeprom_bytearr[0x04:0x24] = server_key (if paired) else unpaired_auth_base
    #eeprom_bytearr[0x24:0x44] = h_client_key (if paired)
    #eeprom_bytearr[0x44:0x53] = pairing_salt (if paired) (below)
    #eeprom_bytearr[0x54:0x74] = car start variable (below)
    eeprom_bytearr[0x80:0xa0] = urandom(0x20)

    if args.car_id != 0xFFFFFFFF:
        car_start_auth = hmac.digest(car_start_base, car_id_bytes, "sha256")
        eeprom_bytearr[0x54:0x74] = car_start_auth

        pairing_auth = hmac.new(unpaired_auth_base, car_id_bytes, "sha256")
        pairing_auth.update(str.encode(args.pair_pin))
        pairing_auth = pairing_auth.digest()

        salt = urandom(0x10)

        subprocess_result = subprocess.run([environ["SECRETS_DIR"]+"/precompute_scram_keys/target/release/precompute_scram_keys", base64.b16encode(pairing_auth), base64.b16encode(salt)], capture_output = True)
        subprocess_result = json.loads(subprocess_result.stdout)
        h_client_key = base64.b16decode(subprocess_result["h_clientkey"])
        server_key = base64.b16decode(subprocess_result["serverkey"])

        eeprom_bytearr[0x04:0x24] = server_key
        eeprom_bytearr[0x24:0x44] = h_client_key
        eeprom_bytearr[0x44:0x54] = salt

        # Write to header file
        with open(args.header_file, "w") as fp:
            fp.write("#ifndef __FOB_SECRETS__\n")
            fp.write("#define __FOB_SECRETS__\n\n")
            fp.write("#define PAIRED 1\n")
            fp.write("#endif\n")
    else:
        eeprom_bytearr[0x04:0x24] = unpaired_auth_base
        eeprom_bytearr[0x54:0x74] = car_start_base
        # Write to header file
        with open(args.header_file, "w") as fp:
            fp.write("#ifndef __FOB_SECRETS__\n")
            fp.write("#define __FOB_SECRETS__\n\n")
            fp.write("#define PAIRED 0\n")
            fp.write("#endif\n")

    with open(args.eeprom_file, "wb") as fp:
        fp.write(eeprom_bytearr)


if __name__ == "__main__":
    main()
