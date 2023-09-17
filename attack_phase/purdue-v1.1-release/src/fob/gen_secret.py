#!/usr/bin/python3 -u

# @file gen_secret
# @author Purdue eCTF Team
# @brief Contains the board link functions for the fob
# @date 2023
#
# This file contains function to generate the secrets for the fob
#
# @copyright Copyright (c) 2023 Purdue eCTF Team

import json
import argparse
from pathlib import Path
import secrets
from typing import List
from ascon.ascon import *
from Crypto.Hash import SHA256
import datetime

fob_secret_config = {
    "FOB_SECRET_SALT": {
        "size": 26,
        "address": 0x300,
        "unpaired": True,
        "secret": True
    },
    "FOB_KEY": {
        "size": 16,
        "address": 0x200,
        "use": "CAR_KEY",
        "unpaired": True,
        "secret": True,
    },
    "RANDOM_SEED": {
        "size": 16,
        "address": 0x210,
        "unpaired": True,
        "secret": False,
    },
    "FOB_PIN_HASH": {
        "size": 32,
        "address": 0x220,
        "function": "hash_pin_ascon",
        "use": "FOB_SECRET_SALT",
        "unpaired": True,
        "secret": True,
    },
    "FOB_STATE": {
        "size": 4,
        "address": 0x240,
        "value": 0,
        "unpaired": True,
        "secret": False
    },
    "FOB_FEATURE_DATA": {
        "size": 1 + (16 * 3),
        "address": 0x244,
        "value": 0,
        "unpaired": True,
        "secret": False
    },
}

used_addresses = [0] * 0x800


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
        address = secrets.randbelow(0x800 - (size + 1))
        address = address & 0xFFFFFFFC

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
    def __init__(self, name, size, address, randomize=True, value=None, use=None, function=None, upsecret=False):
        '''
        Control flow of this module:
            1. Main calls generate_car_secrets
            2. Generate_car_secrets creates invokes this object "Secret" with metadata
                 from the config array in line 10, by enumerating over it.
            3. That is then dumped on EEPROM for use by the car before ensuring there is 
                 no overlap in the secrets.


        This class simply iterates over the config array.
        Check generate_fob_secrets()
        '''
        self.name = name
        self.size = size

        if randomize:
            self.address = get_allocation_address(size)
        else:
            self.address = address

        if upsecret:
            self._generate()
            return

        if value is not None:
            self.value = value.to_bytes(self.size, "little")
        elif use is not None and function is not None:
            if function in globals():
                self.value = globals()[function](secret_value(use))
            else:
                raise ValueError("Function not found")
        elif use is not None:
            self.value = secret_value(use)
        elif function is not None:
            if function in globals():
                self.value = globals()[function]()
            else:
                raise ValueError("Function not found")
        else:
            self._generate()

    def _generate(self):
        self.value = secrets.token_bytes(self.size)

    def range(self):
        return range(self.address, self.address + self.size)

    def check_address(self, address):
        print(address)
        return address in self.range()


def check_for_overlap(secrets: List[Secret]):
    # check for overlap
    for i in range(len(secrets)):
        for j in range(i + 1, len(secrets)):
            if any(secrets[i].check_address(address) for address in secrets[j].range()):
                raise ValueError("Secrets overlap")


pairing_pin = None


def main():
    '''
    This file is compiled as follows:
        python3 gen_secret.py --car-id ${CAR_ID} --pair-pin ${PAIR_PIN} --secret-file 
        ${SECRETS_DIR}/car_secrets.json --header-file inc/secrets.h --paired


    After this file is built, with the following makefile:
                        cp ${SECRETS_DIR}/${CAR_ID}/fob_eeprom.bin ${EEPROM_PATH}

    The data is written on the EEPROM for use by fob.

    Check Secrets interface to see the control flow of this module
    '''
    global pairing_pin
    parser = argparse.ArgumentParser()
    parser.add_argument("--car-id", type=int)
    parser.add_argument("--pair-pin", type=str)
    parser.add_argument("--paired", action="store_true")
    parser.add_argument("--secret-dir", type=Path, required=True)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    if args.paired:
        if args.secret_dir.exists():
            car_dir = args.secret_dir / f"{args.car_id}"
            if car_dir.exists():
                pairing_pin = args.pair_pin
                get_car_secrets(car_dir)
                fob_secrets = generate_fob_secrets(args.debug, True)
                create_eeprom_json(fob_secrets, car_dir)
                create_eeprom_file(fob_secrets, car_dir, args.debug)
                create_header_file(fob_secrets, car_dir, True)
            else:
                raise ValueError("Car directory does not exist")
    else:
        # If the FOB is not paired, EEPROM is populated with random data.
        # IF the FOB is paired, read the secrets of the already existing car.
        # check gen_secrets in car/
        car_dir = args.secret_dir
        fob_secrets = generate_fob_secrets(args.debug, False)
        create_eeprom_json(fob_secrets, car_dir)
        create_eeprom_file(fob_secrets, car_dir, args.debug)
        create_header_file(fob_secrets, car_dir, False)


# Nice ninja variable here.
# If the FOB is paired, use this guy to populate the existing secret from the car
car_eeprom_data = {}


def hash_pin_ascon(salt: bytes = None):
    global pairing_pin
    if pairing_pin is None:
        raise ValueError("Pairing pin not set")
    if salt is not None:
        data = salt + pairing_pin.encode("utf-8")
    else:
        data = pairing_pin.encode("utf-8")
    return ascon_hash(data, variant="Ascon-Hash", hashlength=32)


def hash_pin_sha256(salt: bytes = None):
    global pairing_pin
    if pairing_pin is None:
        raise ValueError("Pairing pin not set")
    if salt is not None:
        data = salt + pairing_pin.encode("utf-8")
    else:
        data = pairing_pin.encode("utf-8")
    return SHA256.new(data).digest()


def get_car_secrets(car_dir: Path):
    global car_eeprom_data
    with open(car_dir / "eeprom.json", "r") as f:
        car_eeprom_data = json.load(f)


def secret_value(name):
    """
    Parameters
    ----------
        name, string, name of the field for which value we need.

    Returns
    -------
        value of the config
    """
    global car_eeprom_data, fob_secrets
    if name == None:
        return None
    if name in car_eeprom_data:
        return bytes.fromhex(car_eeprom_data[name]["value"])
    for secret in fob_secrets:
        if secret.name == name:
            return secret.value
    else:
        return None


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
    with open(car_dir / "fob_eeprom.json", "w") as f:
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
    with open(car_dir / "fob_eeprom.bin", "wb") as f:
        eeprom_data = [0] * 0x800
        # write a bunch of random data into the eeprom
        if not debug:
            for i in range(0x800):
                eeprom_data[i] = secrets.randbelow(0xFF)

        for secret in secrets_list:
            for i in secret.range():
                eeprom_data[i] = secret.value[i - secret.address]

        f.write(bytes(eeprom_data))


def create_header_file(secrets: List[Secret], car_dir: Path, paired: bool = False):
    """
    Parameters
    ----------
        secrets: array of secrets
        car_dir: string of path

    Returns
    -------
        dumps data to a header file to use by fob 
    """
    with open(car_dir / "fob_eeprom_wrapper.h", "w") as f:
        f.write("#ifndef EEPROM_WRAPPER_H\n")
        f.write("#define EEPROM_WRAPPER_H\n\n")
        # define PAIRED 0
        if paired:
            f.write("#define PAIRED 1\n")
        else:
            f.write("#define PAIRED 0\n")

        for secret in secrets:
            f.write(f"#define {secret.name} 0x{secret.address:03X}\n")
            f.write(f"#define {secret.name}_LEN {secret.size}\n")

        f.write("\n#endif\n")


def generate_fob_secrets(debug=False, paired=False):
    """
    Parameters
    ----------
        debug, bool
        paired, bool

    Returns
    -------
        fob_secrets after appending from the config defined on line 10.
    """
    global fob_secrets

    for key, value in fob_secret_config.items():
        if paired:
            fob_secrets.append(Secret(key, value["size"], value["address"], not debug, value.get(
                "value", None), value.get("use", None), value.get("function", None)))
        else:
            if "unpaired" in value and value["unpaired"]:
                fob_secrets.append(Secret(key, value["size"], value["address"], not debug,
                                          value.get("value", None), value.get(
                                              "use", None), value.get("function", None),
                                          value.get("secret", False)))

    # check_for_overlap(fob_secrets)
    return fob_secrets


if __name__ == "__main__":
    fob_secrets = []
    main()
