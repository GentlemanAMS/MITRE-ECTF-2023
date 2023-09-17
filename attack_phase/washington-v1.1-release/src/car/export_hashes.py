import sys
import json

#
# Writes the feature hashes to the car's eeprom... might as well make use of that functionality
#
# Usage:
# python3 export_hashes.py <eeprom_dir> <factory_dir> <car_id>


if(len(sys.argv) != 4):
    print("bad args")
    exit()

eeprom_dir  = sys.argv[1]
factory_dir = sys.argv[2]
car_id      = sys.argv[3]

offset = 0x400

f = open(eeprom_dir, 'wb')

factory_secrets = open(factory_dir, "r")
factory_secrets = json.load(factory_secrets)

car = factory_secrets[f'car{car_id}']

hash_a = bytes.fromhex(car['hash_a'])
hash_b = bytes.fromhex(car['hash_b'])
hash_c = bytes.fromhex(car['hash_c'])

out = b'\xff' * (offset - 1) + b'H' + hash_a + hash_b + hash_c
f.write(out)