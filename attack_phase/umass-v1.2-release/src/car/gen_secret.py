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
import struct
import base64
import argparse
from pathlib import Path

import subprocess
import hmac
from os import urandom, environ

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--car-id", type=int, required=True)
    parser.add_argument("--car-start-base", type=Path, required=True)
    #parser.add_argument("--secret-file", type=Path, required=True)
    parser.add_argument("--header-file", type=Path, required=True)
    parser.add_argument("--eeprom-file", type=Path, required=True)
    args = parser.parse_args()

    with open(args.car_start_base, "rb") as fp:
        car_start_base = fp.read()

    car_id_bytes = struct.pack('<I', args.car_id)

    car_start_auth = hmac.digest(car_start_base, car_id_bytes, "sha256")

    salt = urandom(0x10)

    subprocess_result = subprocess.run([environ["SECRETS_DIR"]+"/precompute_scram_keys/target/release/precompute_scram_keys", base64.b16encode(car_start_auth), base64.b16encode(salt)], capture_output = True)
    subprocess_result = json.loads(subprocess_result.stdout)
    h_client_key = base64.b16decode(subprocess_result["h_clientkey"])
    server_key = base64.b16decode(subprocess_result["serverkey"])

    eeprom_bytearr = bytearray([0xff]*0xa0)
    #eeprom_bytearr[0x00:0x04] = car_id_bytes
    eeprom_bytearr[0x00:0x20] = server_key
    eeprom_bytearr[0x20:0x40] = h_client_key
    eeprom_bytearr[0x40:0x50] = salt
    eeprom_bytearr[0x80:0xa0] = urandom(0x20)

    with open(args.eeprom_file, "wb") as fp:
        fp.write(eeprom_bytearr)

    # Write to header file
    with open(args.header_file, "w") as fp:
        fp.write("#ifndef __CAR_SECRETS__\n")
        fp.write("#define __CAR_SECRETS__\n\n")
        fp.write(f'#define CAR_ID_MACRO {args.car_id}\n\n')
        fp.write("#endif\n")


if __name__ == "__main__":
    main()