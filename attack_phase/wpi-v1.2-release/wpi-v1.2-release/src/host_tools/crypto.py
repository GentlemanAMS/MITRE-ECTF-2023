# Team WPI
#
# 2023
#
# This source code is part of Team WPI's implementation for the 2023 Mitre Embedded CTF challenge.

from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Random import get_random_bytes
import json

TYPE_PACKAGE = 3

def load_secrets(secrets_name: str) -> dict:
    with open(secrets_name, "r") as secrets_file:
        return json.load(secrets_file)

PKT_LEN = 128

NONCE_LEN = 24
TAG_LEN = 16
CIPHERTEXT_LEN = PKT_LEN - NONCE_LEN - TAG_LEN  # Total message - nonce - tag

# Nonce is just made with car ID and feature num
# We only need nonces in the package_tool tool
# This is the only way to predictably test the nonce
# We don't need to worry about replay attacks since once a feature
# is applied, it can't be re-applied.
def gen_random_nonce(car_id: int, feature_num: int):
    top_bits = get_random_bytes(NONCE_LEN - 8)
    bottom_bits = car_id.to_bytes(4, 'little', signed=False)
    if len(bottom_bits) < 4:
        bottom_bits += b'\x00'*(4-len(bottom_bits))
    bottom_bits += feature_num.to_bytes(4, 'little', signed = False)
    return top_bits + bottom_bits

def pack_and_encrypt(type: int, data: bytes, key: bytes, nonce=b""):
    """Encrypt and package a packet

    Parameters:
    type (int): The type of packet to package
    data (bytes): The data to encrypt
    nonce (bytes): Optional.

    Returns:
    bytes: The packaged packet
    """

    if type < 0 or type > 65535:
        print("Invalid type")
        return b''

    length = len(data)

    if length < 0 or length > 80:
        print("Invalid length")
        return b''

    if len(nonce) == 0:
        nonce = gen_random_nonce(1, 1)

    tp_bytes = type.to_bytes(4, byteorder='little')
    #ln_bytes = length.to_bytes(4, byteorder='little')

    #full_data = tp_bytes + ln_bytes + data
    full_data = tp_bytes + data

    (ciphertext, tag) = encrypt(full_data, key, nonce)

    return ciphertext + nonce + tag

def encrypt(data, key, nonce):

    if len(data) < CIPHERTEXT_LEN:
        data += get_random_bytes(CIPHERTEXT_LEN - len(data))

    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(data)

    return ciphertext[:CIPHERTEXT_LEN], tag[:TAG_LEN]

def decrypt(message, key):

    ciphertext = message[:CIPHERTEXT_LEN]
    nonce = message[CIPHERTEXT_LEN:CIPHERTEXT_LEN + NONCE_LEN]
    tag = message[CIPHERTEXT_LEN + NONCE_LEN:]

    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)

    plaintext = cipher.decrypt_and_verify(ciphertext, tag)

    return plaintext


def decrypt_and_unpack(packet: bytes):
    """Decrypt the provided packet and extract the data

    Parameters:
    packet (bytes): The packet to decrypt and unpack

    Returns:
    Tuple(int, bytes): A tuple of the packet type and the decrypted data
    """

    decrypted = decrypt(packet)

    type = decrypted[0:4]
    length = decrypted[4:8]

    tp_int = int.from_bytes(type, byteorder='little')
    ln_int = int.from_bytes(length, byteorder='little')

    if ln_int > 80:
        print("Invalid length received!")
        return (-1, b'')

    data = decrypted[8:ln_int+8]

    return (tp_int, data)