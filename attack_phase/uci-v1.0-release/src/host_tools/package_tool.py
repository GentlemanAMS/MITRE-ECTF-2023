#!/usr/bin/python3 -u

# @file package_tool
# @author Frederich Stine
# @brief host tool for packaging a feature for a fob
# @date 2023
#
# This source file is part of an example system for MITRE's 2023 Embedded
# CTF (eCTF). This code is being provided only for educational purposes for the
# 2023 MITRE eCTF competition, and may not meet MITRE standards for quality.
# Use this code at your own risk!
#
# @copyright Copyright (c) 2023 The MITRE Corporation

import argparse
from encryption import *


# @brief Function to create a new feature package
# @param package_name, name of the file to output package data to
# @param car_id, the id of the car the feature is being packaged for
# @param feature_number, the feature number being packaged
def package(package_name, car_id, feature_number):
    encryptor = Encrypt(f"/secrets/{car_id}_sec_eprom.txt")
    # Pad id lenth to 8 bytes
    car_id_len = len(str(car_id))
    car_id_pad = (8 - car_id_len) * "\0"
    f=0x00

    if feature_number==1:
        f=0x01
    if feature_number==2:
        f=0x02
    if feature_number==3:
        f=0x04

    # Create package to match defined structure on fob
    package_message_bytes = (
        b''.join([f.to_bytes(1, 'big'),str.encode(str(car_id)+car_id_pad),str.encode("\n")])
    )

    # Write data out to package file
    # /package_dir/ is the mounted location inside the container - should not change

    with open(f"/package_dir/{package_name}", "wb") as fhandle:
        fhandle.write(encryptor.encrypt_byte(package_message_bytes))

    print("Feature packaged")


# @brief Main function
#
# Main function handles parsing arguments and passing them to program
# function.
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--package-name", help="Name of the package file", type=str, required=True,
    )
    parser.add_argument(
        "--car-id", help="Car ID", type=int, required=True,
    )
    parser.add_argument(
        "--feature-number",
        help="Number of the feature to be packaged",
        type=int,
        required=True,
    )

    args = parser.parse_args()

    package(args.package_name, args.car_id, args.feature_number)


if __name__ == "__main__":
    main()
