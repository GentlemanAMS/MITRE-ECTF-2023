#!/bin/python3
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import hashlib
import random
import json
import sys


def add_secrets(car):
    key = bytes.fromhex(car['feature_key'])
    seed = bytes.fromhex(car['feature_seed'])

    # make sure that you can always calculate what a feature should be; aka seed the random
    random.seed(seed)

    feat_a = car['id'].to_bytes(1, 'big') + b'\x01' + random.randbytes(30)
    feat_b = car['id'].to_bytes(1, 'big') + b'\x02' + random.randbytes(30)
    feat_c = car['id'].to_bytes(1, 'big') + b'\x03' + random.randbytes(30)

    cipher_a = AES.new(key, AES.MODE_CBC, iv=feat_a[16:])
    cipher_b = AES.new(key, AES.MODE_CBC, iv=feat_b[16:])
    cipher_c = AES.new(key, AES.MODE_CBC, iv=feat_c[16:])

    # encrypt each plaintext
    # car_id + feature_num + ENC(car_id + feature_num + rand(14)) + iv

    pak_a = car['id'].to_bytes(1, 'big') + b'\x01' + cipher_a.encrypt(feat_a[:16]) + feat_a[16:]
    pak_b = car['id'].to_bytes(1, 'big') + b'\x02' + cipher_b.encrypt(feat_b[:16]) + feat_b[16:]
    pak_c = car['id'].to_bytes(1, 'big') + b'\x03' + cipher_c.encrypt(feat_c[:16]) + feat_c[16:]
    
    car['feat_a'] = pak_a.hex()
    car['feat_b'] = pak_b.hex()
    car['feat_c'] = pak_c.hex()

    # get hashes of each plaintext

    m_a = hashlib.sha256()
    m_a.update(feat_a[:16])
    car['hash_a'] = m_a.hexdigest()
    
    m_b = hashlib.sha256()
    m_b.update(feat_b[:16])
    car['hash_b'] = m_b.hexdigest()

    m_c = hashlib.sha256()
    m_c.update(feat_c[:16])
    car['hash_c'] = m_c.hexdigest()

    return car


if(len(sys.argv) != 2):
    print("bad args")
    exit()

secrets_dir = sys.argv[1]

f = open(secrets_dir + '/car_secrets.json', 'w')

car_secrets = {}

for x in range(255):
    car = {}
    car['shared_key'] = get_random_bytes(32).hex()
    car['feature_key'] = get_random_bytes(16).hex()
    car['feature_seed'] = get_random_bytes(32).hex()
    car['id'] = x
    car_secrets['car' + str(x)] = add_secrets(car)

f.write(json.dumps(car_secrets))
print(car_secrets)
