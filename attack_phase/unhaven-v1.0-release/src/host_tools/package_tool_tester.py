# This is a tool to test if the package_tool file works correctly.

import json
from Crypto.Cipher import AES

SECRETS_JSON_PATH = "/secrets/secrets.json"
PACKED_EXPORT_PATH = "."

def unpackage(filepath):
    with open(SECRETS_JSON_PATH, "r") as fhandle:
        secrets = json.load(fhandle)
    # This is the key we encrypt out stuff with
    feature_encryption_key = secrets["feature_unlock_key"]
    plaintext, tag = aes_cipher = AES.new(feature_encryption_key, AES.MODE_ECB)


    with open(f"{PACKED_EXPORT_PATH}/{filepath}", "wb") as fhandle:
        fhandle.write(plaintext)

    ciphertext, tag = aes_cipher.decrypt(car_secret_bytes)

    print(ciphertext, type(ciphertext))



    print()
