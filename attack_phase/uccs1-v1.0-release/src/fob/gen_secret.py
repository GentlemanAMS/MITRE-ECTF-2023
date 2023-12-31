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


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--car-id", type=int)
    parser.add_argument("--pair-pin", type=str)
    parser.add_argument("--secret-file", type=Path)
    parser.add_argument("--header-file", type=Path)
    parser.add_argument("--paired", action="store_true")
    args = parser.parse_args()
    
    
    if args.paired:
        
        with open(args.secret_file, "r") as fp:
            secrets = json.load(fp)
            car_secret = secrets[str(args.car_id)]
            
            psim = secrets["psim"]
            hsim = secrets["hsim"] 
            tsim = secrets["tsim"] 
            fob_sec = secrets["fob_sec"]
            passwd = secrets["passwd"]

        # Write to header file
        with open(args.header_file, "w") as fp:
            fp.write("#ifndef __FOB_SECRETS__\n")
            fp.write("#define __FOB_SECRETS__\n\n")
            fp.write("#define PAIRED 1\n") # need randomization and protection
            fp.write(f'#define PAIR_PIN "{args.pair_pin}"\n')
            fp.write(f'#define CAR_ID "{args.car_id}"\n')
            fp.write(f'#define CAR_SECRET "{car_secret}"\n\n')

            fp.write('#define PASSWORD "{passwd}"\n\n') # need protection

            fp.write(f'#define PSIM "{psim}"\n\n')
            fp.write(f'#define HSIM "{hsim}"\n\n')
            fp.write(f'#define TSIM "{tsim}"\n\n')
            fp.write('#define FSEC "{fob_sec}"\n\n')

            fp.write("#endif\n")
    else:
        # Write to header file
        with open("/secrets/global_secrets.txt","r") as f:
            lines = f.read()
            fob_sec = lines.split(',')[0]
            psim = lines.split(',')[1]
            hsim = lines.split(',')[2]
            tsim = lines.split(',')[3]
                          

        with open(args.header_file, "w") as fp:
            fp.write("#ifndef __FOB_SECRETS__\n")
            fp.write("#define __FOB_SECRETS__\n\n")
            fp.write("#define PAIRED 0\n")
            fp.write('#define PAIR_PIN "000000"\n')
            fp.write('#define CAR_ID "000000"\n')
            fp.write('#define CAR_SECRET "000000"\n\n')

            fp.write('#define FSEC "{fob_sec}"\n\n')
            fp.write(f'#define HSIM "{hsim}"\n\n')
            fp.write(f'#define PSIM "{psim}"\n\n')
            fp.write(f'#define TSIM "{tsim}"\n\n')

            fp.write("#endif\n")


if __name__ == "__main__":
    main()
