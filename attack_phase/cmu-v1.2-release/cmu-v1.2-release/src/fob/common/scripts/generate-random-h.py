# Generate a eeprom_otp.h source file everytime before make happens.
# Put 288 random sequence addresses.
# Find a way to update the bytes after bootloader with random stuff.

import sys
import secrets
import logging
import json
import header_parser
import argparse

logging.basicConfig(level=logging.DEBUG)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("device", help="car or fob")
    parser.add_argument("out_header", help="header containing the macros for usage")
    parser.add_argument("out_addresses_json", help="json file containing the key addresses")
    args = parser.parse_args()

    start = 0x22400 - (0x400 * 16) # Use last 16 pages.
    end = 0x22400

    if args.device == 'car':
        total_key_size = 0x120
        eeprom_key_sizes = [
            ('EEPROM_CAR_ID', 4),
            ('EEPROM_NONCE_SEED', 4),

            ('EEPROM_CAR_ENCRYPTION_PRIVATE_KEY', 32),
            ('EEPROM_CAR_SIGNATURE_PRIVATE_KEY', 32),

            ('EEPROM_PAIRED_FOB_ENCRYPTION_PUBLIC_KEY', 32),
            ('EEPROM_PAIRED_FOB_SIGNATURE_PUBLIC_KEY', 32),

            ('EEPROM_DEPLOYMENT_SIGNATURE_PUBLIC_KEY', 32),
        ]
    elif args.device == 'fob':
        total_key_size = 0x1C0
        eeprom_key_sizes = [
            ('EEPROM_IS_PAIRED_FOB', 4),

            ('EEPROM_CAR_ID', 4),

            ('EEPROM_FEATURE_BITVEC', 4),

            ('EEPROM_UNPAIRED_FOB_ENCRYPTION_PRIVATE_KEY', 32),

            ('EEPROM_PAIRED_FOB_ENCRYPTION_PRIVATE_KEY', 32),
            ('EEPROM_PAIRED_FOB_SIGNATURE_PRIVATE_KEY', 32),

            ('EEPROM_CAR_ENCRYPTION_PUBLIC_KEY', 32),
            ('EEPROM_CAR_SIGNATURE_PUBLIC_KEY', 32),

            ('EEPROM_DEPLOYMENT_SIGNATURE_PUBLIC_KEY', 32),
            ('EEPROM_UNPAIRED_FOB_ENCRYPTION_PUBLIC_KEY', 32),

            ('EEPROM_CAR_PIN_HASH', 64),
            ('EEPROM_CAR_PIN_HASH_KEY', 64),
        ]
    else:
        raise Exception(f'device must be car or fob but found {args.device}')

    addresses = []
    for i in range(total_key_size): #1728/8
        addresses.append(secrets.randbelow((end - start)) + start)     # To generate a random number between start and end

    eeprom_addrs = header_parser.parse_header('inc/eeprom.h')

    filecontent = ''

    for (name, key_size) in eeprom_key_sizes:
        addr = eeprom_addrs[name]

        for idx in range(key_size):
            filecontent += f'#define {name}_OTP_{idx} {addresses[addr + idx]}\n'

        filecontent += f'\nstatic void xor_{name.lower()}(unsigned char *data) {{\n'
        for idx in range(key_size):
            filecontent += f'    data[{idx}] ^= *(unsigned char *)({name}_OTP_{idx});\n'
        filecontent += '}\n\n'

    writer = open(args.out_header, "w")
    writer.write(filecontent)
    writer.close()

    tmpfile = open(args.out_addresses_json, "w")
    tmpfile.write(json.dumps(addresses))
    tmpfile.close()

if __name__ == '__main__':
    main()
