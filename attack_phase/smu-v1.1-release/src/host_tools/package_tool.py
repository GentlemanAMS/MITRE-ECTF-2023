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
import json
from monocypher import lock, generate_key, signature_sign


# @brief Function to obtain the stored secrets
# @param car_id, the id for the car
def retrieve_secrets(car_id) -> tuple[bytes, bytes]:
    # Load the car secrets
    with open(f"/secrets/carfob_secrets.json", "r") as fhandle:
        carfob_secrets = json.load(fhandle)
        car_link_key = bytes.fromhex(carfob_secrets[car_id]["link_key"])

    # Load the CA signature
    with open(f"/secrets/ca_kp.json", "r") as fhandle:
        ca_kp = json.load(fhandle)
        ca_sk = bytes.fromhex(ca_kp["sk"])

    return car_link_key, ca_sk


# @brief Function to create a new feature package
# @param package_name, name of the file to output package data to
# @param car_id, the id of the car the feature is being packaged for
# @param feature_number, the feature number being packaged
def package(package_name, car_id, feature_number):
    # Make sure they are at most 1 byte long
    if not 0 <= int(car_id) <= 0xFF:
        raise ValueError("Car ID must be 1 byte long")

    if not 0 <= feature_number <= 0xFF:
        raise ValueError("Feature number must be 1 byte long")

    # Retrieve secrets
    car_link_key, ca_sk = retrieve_secrets(car_id)

    # Create package to match defined structure on fob
    package_message_bytes = str.encode(car_id) + feature_number.to_bytes(1, "little")

    # nonce generation
    nonce = generate_key(length=24)

    # Encrypt the package
    mac, package_encrypted_bytes = lock(car_link_key, nonce, package_message_bytes)

    print(
        f"Car: {car_id}, Feature: {feature_number}, Encrypted package: {package_encrypted_bytes}"
    )

    # Sign the plaintext package for use during starting of car
    sig = signature_sign(ca_sk, package_message_bytes)

    print(f"Signature: {sig}, length: {len(sig)}")

    # Write data out to package file
    # /package_dir/ is the mounted location inside the container - should not change
    # nonce (24 bytes) + mac (16 bytes) + package_encrypted_bytes (2 bytes) + sig (64 bytes)
    with open(f"/package_dir/{package_name}", "wb") as fhandle:
        fhandle.write(nonce + mac + package_encrypted_bytes + sig)

    print("Feature packaged")


# @brief Main function
#
# Main function handles parsing arguments and passing them to program
# function.
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--package-name",
        help="Name of the package file",
        type=str,
        required=True,
    )
    parser.add_argument(
        "--car-id",
        help="Car ID",
        type=str,
        required=True,
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
