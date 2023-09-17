#!/usr/bin/python3 -u

# @file gen_secret
# @author Purdue eCTF Team
# @brief Generates secret for car
# @date 2023
#
# This file contains the script for generating the secret for the car
#
# @copyright Copyright (c) 2023 Purdue eCTF Team 

import json
import argparse
from pathlib import Path
import secrets
from typing import List
from ascon.ascon import *
from Crypto.Hash import SHA256

# Contains various options for the config for car
car_secret_config = {
    "CAR_SECRET_SALT": {
        "size": 48,
        "address": 0x300,
        "store": True,
    },
    "CAR_KEY": {
        "size": 16,
        "address": 0x200,
        "store": True,
    },
    "RANDOM_SEED": {
        "size": 16,
        "address": 0x210,
        "store": True,
    },
    "FEATURE_KEY_1": {
        "size": 16,
        "address": 0x0,
        "store": False,
    },
    "FEATURE_KEY_2": {
        "size": 16,
        "address": 0x10,
        "store": False,
    },
    "FEATURE_KEY_3": {
        "size": 16,
        "address": 0x20,
        "store": False,
    },
    "FEATURE_KEY_1_HASH": {
        "size": 32,
        "address": 0x220,
        "function": "hash_pin_ascon",
        "uses": ["FEATURE_KEY_1", "CAR_SECRET_SALT"],
        "store": True,
    },
    "FEATURE_KEY_2_HASH": {
        "size": 32,
        "address": 0x240,
        "function": "hash_pin_ascon",
        "uses": ["FEATURE_KEY_2", "CAR_SECRET_SALT"],
        "store": True,
    },
    "FEATURE_KEY_3_HASH": {
        "size": 32,
        "address": 0x260,
        "function": "hash_pin_ascon",
        "uses": ["FEATURE_KEY_3", "CAR_SECRET_SALT"],
        "store": True,
    },
    "CAR_DEFENSE": {
        "size": 4,
        "value": 0,
        "address": 0x280,
        "store": True,
    },
}

used_addresses = [0] * 0x700


def get_allocation_address(size):
    """
    Parameters
    ----------
        size: range of memory

    Returns
    -------
        random address that is 4 aligned and not in use
    """
    while True:
        # Find a random address, loop to see if used, if true break else return and update
        # used_address array. check line 73.
        address = secrets.randbelow(0x700 - (size + 2))
        address = address & 0xFFFFFFFC

        # round off size to nearest multiple of board
        size = (size + 3) & 0xFFFFFFFC

        is_used = False
        for address1 in range(address, address + size):
            if used_addresses[address1] == 1:
                is_used = True
                break

        if is_used:
            continue

        for address1 in range(address, address + size):
            used_addresses[address1] = 1
        return address


class Secret:
    def __init__(self, name, size, address, randomize=True,
                 value=None, function=None, uses=None, store=True):
        '''
        Control flow of this module:
            1. Main calls generate_car_secrets
            2. Generate_car_secrets creates invokes this object "Secret" with metadata
                 from the config array in line 10, by enumerating over it.
            3. That is then dumped on EEPROM for use by the car before ensuring there is 
                 no overlap in the secrets.


        This class simply iterates over the config array.
        Check generate_car_secrets()
        '''

        self.name = name
        self.size = size
        self.store = store
        # If store is set to true, get allocation address randomly until an avail. address
        # exists, and update used_addresses array.
        if store:
            if randomize:
                self.address = get_allocation_address(size)
            else:
                self.address = address
        else:
            self.address = address

        if value is not None:
            self.value = value.to_bytes(self.size, "little")
        elif uses is not None and function is not None:
            if function not in globals():
                raise ValueError("Function not found")
            # if uses not in [s.name for s in car_secrets]:
            #     raise ValueError("Secret not found")
            used_value = []
            if isinstance(uses, list):
                for use in uses:
                    used_value.append(get_car_secret(use).value)
            else:
                used_value.append(get_car_secret(uses).value)
            if len(used_value) == 1:
                self.value = globals()[function](used_value[0])
            elif len(used_value) == 2:
                self.value = globals()[function](used_value[0], used_value[1])
        elif uses is not None:
            if uses not in car_secrets:
                raise ValueError("Secret not found")
            used_value = get_car_secret(uses).value
            self.value = used_value
        elif function is not None:
            if function not in globals():
                raise ValueError("Function not found")
            self.value = globals()[function]()
        else:
            self._generate()

    def _generate(self):
        self.value = secrets.token_bytes(self.size)

    def range(self):
        return range(self.address, self.address + self.size)

    def check_address(self, address):
        print(address)
        return address in self.range()


def hash_pin_ascon(data_to_hash, salt=b""):
    if salt != b"":
        data_to_hash = salt + data_to_hash
    return ascon_hash(data_to_hash, variant="Ascon-Hash", hashlength=32)


def hash_pin_sha256(data_to_hash, salt=b""):
    if salt != b"":
        data_to_hash = salt + data_to_hash
    return SHA256.new(data_to_hash).digest()


def get_car_secret(name):
    global car_secrets
    for secret in car_secrets:
        if secret.name == name:
            return secret
    raise ValueError("Secret not found")


def check_for_overlap(secrets: List[Secret]):
    # check for overlap
    for i in range(len(secrets)):
        for j in range(i + 1, len(secrets)):
            if secrets[i].store and secrets[i].store:
                if any(secrets[i].check_address(address) for address in secrets[j].range()):
                    raise ValueError("Secrets overlap")


def main():
    '''
    This file is compiled as follows:
        python3 gen_secret.py --car-id ${CAR_ID} --secret-file 
        ${SECRETS_DIR}/car_secrets.json --header-file inc/secrets.h

    After this file is built, with the following makefile:
        ${SECRETS_DIR}/${CAR_ID}/eeprom.bin ${EEPROM_PATH}

    The data is written on the EEPROM for use by car.
    '''

    # Add arguments to the build tools with secret and header file

    parser = argparse.ArgumentParser()
    parser.add_argument("--car-id", type=int, required=True)
    parser.add_argument("--secret-dir", type=Path, required=True)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    # Open existing secret files if it exists, else initialize

    if args.secret_dir.exists():
        # let's create a folder for the car-id
        car_dir = args.secret_dir / str(args.car_id)
        car_dir.mkdir(parents=True, exist_ok=True)

        # let's create a file for the car secrets
        secrets = generate_car_secrets(args.debug)

        create_eeprom_file(secrets, car_dir, args.debug)
        create_eeprom_json(secrets, car_dir)
        create_header_file(secrets, car_dir)


def create_eeprom_json(secrets: List[Secret], car_dir: Path):
    """
    Parameters
    ----------
        secrets: array of secrets
        car_dir: string of path

    Returns
    -------
        dumps json to eeprom
    """
    with open(car_dir / "eeprom.json", "w") as f:
        eeprom_data = {}
        for secret in secrets:
            eeprom_data[secret.name] = {
                "address": secret.address,
                "size": secret.size,
                "value": secret.value.hex()
            }

        json.dump(eeprom_data, f, indent=4)


def create_eeprom_file(secrets_list: List[Secret], car_dir: Path, debug: bool):
    """
    Parameters
    ----------
        secrets_list: array of secrets
        car_dir: string of path
        debug: bool, set to true for nothing

    Returns
    -------
        dumps json to eeprom
    """
    with open(car_dir / "eeprom.bin", "wb") as f:
        eeprom_data = [0] * 0x700
        # write a bunch of random data into the eeprom
        if not debug:
            for i in range(0x700):
                eeprom_data[i] = secrets.randbelow(0xFF)

        for secret in secrets_list:
            if secret.store:
                for i in secret.range():
                    eeprom_data[i] = secret.value[i - secret.address]

        f.write(bytes(eeprom_data))


def create_header_file(secrets: List[Secret], car_dir: Path):
    """
    Parameters
    ----------
        secrets: array of secrets
        car_dir: string of path

    Returns
    -------
        dumps data to a header file to use by cars firmware
    """
    print(car_dir / "eeprom_wrapper.h")
    with open(car_dir / "eeprom_wrapper.h", "w") as f:
        f.write("#ifndef EEPROM_WRAPPER_H\n")
        f.write("#define EEPROM_WRAPPER_H\n\n")

        for secret in secrets:
            if secret.store:
                f.write(f"#define {secret.name} 0x{secret.address:03X}\n")
                f.write(f"#define {secret.name}_LEN {secret.size}\n")

        f.write("\n#endif\n")


def generate_car_secrets(debug):
    """
    Parameters
    ----------
        debug, bool, does nothing

    Returns
    -------
        car_secrets after appending from the config defined on line 10.
    """
    global car_secrets
    car_secrets = []

    for key, value in car_secret_config.items():
        # Check Secret class for a complete work-flow of this module.
        car_secrets.append(Secret(key, value["size"], value["address"],
                                  not debug, value.get("value", None), value.get(
                                      "function", None),
                                  value.get("uses", None), value.get("store", False)))

    # check_for_overlap(car_secrets)
    return car_secrets


if __name__ == "__main__":
    car_secrets = []
    main()
