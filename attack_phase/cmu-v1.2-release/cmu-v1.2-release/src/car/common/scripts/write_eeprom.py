#!/usr/bin/python3 -u

# 2023 eCTF
# EEPROM Encrypt Tool
# PPP Team, CMU
import base64
import json
import logging
from pathlib import Path
import os
import argparse
import sys
import header_parser
logging.basicConfig(level=logging.INFO)

PARED_START_ADDR = 0x8000

def load_key(key_file, bootloader_file):
    key_addresses = json.loads(open(key_file).read())
    bootloader_bin = open(bootloader_file, "rb").read()
    key = b""
    for address in key_addresses:
        key += bytes([bootloader_bin[address - PARED_START_ADDR]])
    return key

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("device", help="car or fob")
    parser.add_argument("in_eeprom", help="plaintext eeprom file")
    parser.add_argument("in_firmware", help="firmware file")
    parser.add_argument("key_file", help="json file containing the addresses of the keys")
    parser.add_argument("out_eeprom", help="encrypted eeprom file")
    args = parser.parse_args()

    if args.device == "car":
        key_size = 0x120
    elif args.device == "fob":
        key_size = 0x1C0
    else:
        raise Exception(f'device must be car or fob but found {args.device}')

    key = load_key(args.key_file, args.in_firmware)
    assert(len(key) == key_size)

    eeprom_file = list(open(args.in_eeprom, 'rb').read())

    for i in range(key_size):
        eeprom_file[i] ^= key[i]

    with open(args.out_eeprom, 'wb') as f:
        f.write(bytes(eeprom_file))


if __name__ == "__main__":
    main()
