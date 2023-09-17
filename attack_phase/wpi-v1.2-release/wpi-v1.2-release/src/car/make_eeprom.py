
import argparse
import json
import sys
import struct

from pathlib import Path
from nacl.signing import SigningKey
from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256

KEY_SIZE = 32
SEED_SIZE = 32
NONCE_SIZE = 24
PASS_SIZE = 32
VERIFYING_KEY_SIZE = 32
SALT_SIZE = 16

PARED_EEPROM_SIZE = 0x700
TOTAL_EEPROM_SIZE = 0x800

SYM_KEY_EEPROM_ADDR = 0x00
SEED_EEPROM_ADDR = 0x20
NONCE_ID_EEPROM_ADDR = 0x40
UNLOCK_PASSWD_EEPROM_ADDR = 0x58

CAR_ID_EEPROM_ADDR = 0x78
PAIR_PIN_EEPROM_ADDR = 0x7C
PAIRED_STATUS_EEPROM_ADDR = 0x84

VERIFYING_KEY_EEPROM_ADDR = 0x200

PIN_DERIVED_KEY_SALT_ADDR = 0x280
FOB_ID_ADDR = 0x2A0
PIN_PROTECTED_PAYLOAD_NONCE_ADDR = 0x2C0
PIN_PROTECTED_PAYLOAD_ADDR = 0x300

PW_DERIVED_KEY_SALT_ADDR = 0x400
PW_PROTECTED_PAYLOAD_NONCE_ADDR = 0x420
PW_PROTECTED_PAYLOAD_ADDR = 0x440

PBKDF2_ROUNDS = 1000

"""
This is going to look quite different than before.

Secrets file will now be JSON with all data encoded in hex (since JSON doesn't support
raw bytes). This is to allow storing data for various devices

For ALL devices:
a random seed, and random nonce.
These are stored in EEPROM.
We don't care about storing them in the secrets file since these are unique per device.

For unpaired fobs, we're done.

For cars:
Generate password and a symmetric key.
Store these in the SECRETS FILE as well as the EEPROM.
Store standard info, the password + symmetric key, and the car ID

For paired fob:
Load password and symmetric key
Store standard info, the password + symmetric key, car ID, and pairing pin.
Also set paired status to 1
"""

def gen_car_json_key(car_id: int) -> str:
    return f'car_{car_id}'

def write_paired_fob(eeprom: bytearray, secrets_data: dict, seed: bytes, nonce: bytes, car_id: int, pair_pin: str):
    car_secrets = secrets_data.get(gen_car_json_key(car_id))

    if car_secrets is None:
        raise RuntimeError("No secrets found for car %d" % car_id)

    key_hex: str = car_secrets["key"]
    pass_hex: str = car_secrets["pass"]
    manu_verify_key_hex: str = car_secrets["manu_verify_key"]

    key = bytes.fromhex(key_hex)
    password = bytes.fromhex(pass_hex)
    manu_verify_key = bytes.fromhex(manu_verify_key_hex)

    eeprom[SYM_KEY_EEPROM_ADDR:SYM_KEY_EEPROM_ADDR+KEY_SIZE] = key
    eeprom[SEED_EEPROM_ADDR:SEED_EEPROM_ADDR+SEED_SIZE] = seed
    eeprom[NONCE_ID_EEPROM_ADDR:NONCE_ID_EEPROM_ADDR+NONCE_SIZE] = nonce
    eeprom[UNLOCK_PASSWD_EEPROM_ADDR:UNLOCK_PASSWD_EEPROM_ADDR+PASS_SIZE] = password
    eeprom[CAR_ID_EEPROM_ADDR:CAR_ID_EEPROM_ADDR+4] = struct.pack('<I', car_id)
    eeprom[PAIRED_STATUS_EEPROM_ADDR:PAIRED_STATUS_EEPROM_ADDR+4] = struct.pack('<I', 1)
    eeprom[VERIFYING_KEY_EEPROM_ADDR:VERIFYING_KEY_EEPROM_ADDR+VERIFYING_KEY_SIZE] = manu_verify_key
    fob_id = get_random_bytes(32)
    eeprom[FOB_ID_ADDR:FOB_ID_ADDR+32] = fob_id

    pin_payload_salt = get_random_bytes(SALT_SIZE)
    pin_payload_derived_key = PBKDF2(pair_pin, pin_payload_salt, dkLen=32, count=PBKDF2_ROUNDS, hmac_hash_module=SHA256)
    pin_payload_nonce = get_random_bytes(24)

    cipher = ChaCha20_Poly1305.new(key=pin_payload_derived_key, nonce=pin_payload_nonce)
    cipher.update(struct.pack('<I', car_id) + fob_id)

    pin_payload_ciphertext, pin_payload_tag = cipher.encrypt_and_digest(b"Correct Pair PIN")

    eeprom[PIN_DERIVED_KEY_SALT_ADDR:PIN_DERIVED_KEY_SALT_ADDR+SALT_SIZE] = pin_payload_salt
    eeprom[PIN_PROTECTED_PAYLOAD_NONCE_ADDR:PIN_PROTECTED_PAYLOAD_NONCE_ADDR+24] = pin_payload_nonce
    eeprom[PIN_PROTECTED_PAYLOAD_ADDR:PIN_PROTECTED_PAYLOAD_ADDR+32] = pin_payload_ciphertext + pin_payload_tag

    # test
    pin_payload_derived_key = PBKDF2(
        pair_pin, 
        eeprom[PIN_DERIVED_KEY_SALT_ADDR:PIN_DERIVED_KEY_SALT_ADDR+SALT_SIZE], 
        dkLen=32, 
        count=PBKDF2_ROUNDS, 
        hmac_hash_module=SHA256
    )
    pin_payload_nonce = eeprom[PIN_PROTECTED_PAYLOAD_NONCE_ADDR:PIN_PROTECTED_PAYLOAD_NONCE_ADDR+24]

    cipher = ChaCha20_Poly1305.new(key=pin_payload_derived_key, nonce=pin_payload_nonce)
    cipher.update(eeprom[CAR_ID_EEPROM_ADDR:CAR_ID_EEPROM_ADDR+4] + eeprom[FOB_ID_ADDR:FOB_ID_ADDR+32])
    encrypted = eeprom[PIN_PROTECTED_PAYLOAD_ADDR:PIN_PROTECTED_PAYLOAD_ADDR+32]

    decrypted = cipher.decrypt_and_verify(encrypted[:16], encrypted[16:])
    print(decrypted)

def write_unpaired_fob(eeprom: bytearray, seed: bytes, nonce: bytes):
    eeprom[SYM_KEY_EEPROM_ADDR:SYM_KEY_EEPROM_ADDR+KEY_SIZE] = b'\x00' * KEY_SIZE
    eeprom[SEED_EEPROM_ADDR:SEED_EEPROM_ADDR+SEED_SIZE] = seed
    eeprom[NONCE_ID_EEPROM_ADDR:NONCE_ID_EEPROM_ADDR+NONCE_SIZE] = nonce
    eeprom[PAIRED_STATUS_EEPROM_ADDR:PAIRED_STATUS_EEPROM_ADDR+4] = struct.pack('<I', 0)

def write_car(eeprom: bytearray, secrets_data: dict, seed: bytes, nonce: bytes, car_id: int):
    # Gen password
    # Gen secret key
    with open("/dev/urandom", "rb") as f:
        key = f.read(KEY_SIZE)
        password = f.read(PASS_SIZE)
    
    signing_key = SigningKey.generate()
    secrets_data[gen_car_json_key(car_id)] = {
        "key": key.hex(),
        "pass": password.hex(),
        "manu_signing_key": bytes(signing_key).hex(),
        "manu_verify_key": bytes(signing_key.verify_key).hex()
    }

    eeprom[SYM_KEY_EEPROM_ADDR:SYM_KEY_EEPROM_ADDR+KEY_SIZE] = key
    eeprom[SEED_EEPROM_ADDR:SEED_EEPROM_ADDR+SEED_SIZE] = seed
    eeprom[NONCE_ID_EEPROM_ADDR:NONCE_ID_EEPROM_ADDR+NONCE_SIZE] = nonce
    eeprom[CAR_ID_EEPROM_ADDR:CAR_ID_EEPROM_ADDR+4] = struct.pack('<I', car_id)
    eeprom[VERIFYING_KEY_EEPROM_ADDR:VERIFYING_KEY_EEPROM_ADDR+VERIFYING_KEY_SIZE] = bytes(signing_key.verify_key)

    pw_payload_salt = get_random_bytes(SALT_SIZE)
    pw_payload_derived_key = PBKDF2(password, pw_payload_salt, dkLen=32, count=PBKDF2_ROUNDS, hmac_hash_module=SHA256)
    pw_payload_nonce = get_random_bytes(24)

    cipher = ChaCha20_Poly1305.new(key=pw_payload_derived_key, nonce=pw_payload_nonce)
    cipher.update(struct.pack('<I', car_id))

    pw_payload_ciphertext, pw_payload_tag = cipher.encrypt_and_digest(b"Correct Password")

    eeprom[PW_DERIVED_KEY_SALT_ADDR:PW_DERIVED_KEY_SALT_ADDR+SALT_SIZE] = pw_payload_salt
    eeprom[PW_PROTECTED_PAYLOAD_NONCE_ADDR:PW_PROTECTED_PAYLOAD_NONCE_ADDR+24] = pw_payload_nonce
    eeprom[PW_PROTECTED_PAYLOAD_ADDR:PW_PROTECTED_PAYLOAD_ADDR+32] = pw_payload_ciphertext + pw_payload_tag

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--type", type=str, required=True) # "car" or "fob"
    parser.add_argument("--car-id", type=int)
    parser.add_argument("--pair-pin", type=str)
    parser.add_argument("--secret-file", type=Path, required=True)
    parser.add_argument("--eeprom-file", type=Path, required=True)
    parser.add_argument("--paired", action="store_true") # only if "fob"

    args = parser.parse_args()

    try:

        # Generate seed and nonce
        with open("/dev/urandom", "rb") as f:
            seed = f.read(SEED_SIZE)
            nonce = f.read(NONCE_SIZE)

        eeprom = bytearray(PARED_EEPROM_SIZE)
        secrets_data = None

        with open(args.secret_file, 'r') as f:
            secrets_data = json.load(f)

        print("INFO: Loaded secrets from %s" % args.secret_file)
        
        if args.type == "fob":
            if args.paired:
                if args.car_id is None:
                    raise RuntimeError("Car ID was not specified!")
                if not args.pair_pin:
                    raise RuntimeError("Pairing PIN was not specified!")
                write_paired_fob(eeprom, secrets_data, seed, nonce, args.car_id, args.pair_pin)
            else:
                write_unpaired_fob(eeprom, seed, nonce)
        elif args.type == "car":
            if args.car_id is None:
                raise RuntimeError("Car ID was not specified!")
            write_car(eeprom, secrets_data, seed, nonce, args.car_id)
        else:
            raise RuntimeError("Unknown device type: %s" % args.type)
        
        print("INFO: Generated secrets")

        with open(args.secret_file, "w") as f:
            json.dump(secrets_data, f, sort_keys=True, indent=4)

        print("INFO: Saved secrets to %s" % args.secret_file)

        print("INFO: Generated %d bytes of EEPROM data" % len(eeprom))

        # The EEPROM is technically 0x800 bytes, but the last 0x100 bytes are reserved.
        if len(eeprom) > PARED_EEPROM_SIZE:
            raise RuntimeError("EEPROM is too large! Size limit: %d" % PARED_EEPROM_SIZE)

        # Pad EEPROM wiht 0s
        eeprom += b'\x00'*(TOTAL_EEPROM_SIZE-len(eeprom))
        with open(args.eeprom_file, "wb") as f:
            f.write(eeprom)
        print("INFO: Saved EEPROM to %s" % args.eeprom_file)
    except Exception as e:
        print("ERROR: Generating EEPROM failed!", file=sys.stderr)
        raise e


if __name__ == "__main__":
    main()