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
import secrets
from pathlib import Path

def main():

    debug = True

    parser = argparse.ArgumentParser()
    parser.add_argument("--car-id", type=int)
    parser.add_argument("--pair-pin", type=str)
    parser.add_argument("--secret-file", type=Path)
    parser.add_argument("--header-file", type=Path)
    parser.add_argument("--paired", action="store_true")
    args = parser.parse_args()

    f = open('/secrets/car_secrets.json', "r")
    factory_secrets = json.load(f)

    dev_entropy = '{' + str([x for x in secrets.token_bytes(16)])[1:-1] + '}' #16 byte array

    if(args.paired):

        car = factory_secrets['car'+str(args.car_id)]
        pair_sec    = '{' + str([x for x in bytes.fromhex(car['shared_key'])])[1:-1] + '}'
        
        paired_secrets = f'''
        #ifndef __FOB_SECRETS__
        #define __FOB_SECRETS__
        
        #define PAIRED 1
        #define SEC_PAIR_PIN 0x{args.pair_pin}
        #define SEC_CAR_ID {args.car_id}
        #define SEC_PAIR_SECRET {pair_sec}
        #define SEC_FACTORY_ENTROPY {dev_entropy}

        #endif
        '''

    else:
        paired_secrets = f'''
        #ifndef __FOB_SECRETS__
        #define __FOB_SECRETS__
        
        #define PAIRED 0
        #define SEC_PAIR_PIN 0x00
        #define SEC_CAR_ID 255
        #define SEC_PAIR_SECRET {{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}
        #define SEC_FACTORY_ENTROPY {dev_entropy}

        #endif
        '''

        # Write to header file
    with open(args.header_file, "w") as fp:
            fp.write(paired_secrets)


if __name__ == "__main__":
    main()
