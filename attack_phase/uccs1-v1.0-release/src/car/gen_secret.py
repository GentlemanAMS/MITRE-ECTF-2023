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
import random
from pathlib import Path
import os



def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--car-id", type=int, required=True)
    parser.add_argument("--secret-file", type=Path, required=True)
    parser.add_argument("--header-file", type=Path, required=True)
    args = parser.parse_args()
    
    # Open the secret file if it exists
    print(args.secret_file)

    if args.secret_file.exists():
        with open(args.secret_file, "r") as fp:
            secrets = json.load(fp)
    else:
        secrets = {}
    # pre-shared key
    with open("/secrets/global_secrets.txt","r") as f:
      lines = f.read()
      fob_sec = lines.split(',')[0]
      psim = lines.split(',')[1]
      hsim = lines.split(',')[2]
      tsim = lines.split(',')[3]
      passwd = lines.split(',')[4]

    

    # Add dummy secret
    # need randomization
    car_secret = random.randint(1000,591000)
    secrets[str(args.car_id)] = car_secret
    secrets["psim"] = psim
    secrets["hsim"] = hsim
    secrets["tsim"] = tsim 
    secrets["fob_sec"] = fob_sec 
    secrets["passwd"] = passwd
    
        
    # Save the secret file
    with open(args.secret_file, "w") as fp:
        json.dump(secrets, fp, indent=4)

    # Write to header file
    with open(args.header_file, "w") as fp:
        fp.write("#ifndef __CAR_SECRETS__\n")
        fp.write("#define __CAR_SECRETS__\n\n")
        fp.write(f"#define CAR_SECRET {car_secret}\n\n")
        fp.write(f'#define CAR_ID "{args.car_id}"\n\n')

        fp.write('#define PASSWORD "{passwd}"\n\n')

        fp.write(f'#define PSIM "{psim}"\n\n')
        fp.write(f'#define TSIM "{tsim}"\n\n')
        fp.write(f'#define HSIM "{hsim}"\n\n')
        fp.write("#endif\n")


if __name__ == "__main__":
    main()
