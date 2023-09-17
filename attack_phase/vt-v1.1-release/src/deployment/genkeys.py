from ecdsa import SigningKey, SECP256k1, util
import os
import hashlib


x_coord = ""
y_coord = ""

while x_coord == "" or x_coord.find("00") != -1 or y_coord == "" or y_coord.find("00") != -1:
    rng = util.PRNG(os.urandom(256))
    sk = SigningKey.generate(curve=SECP256k1, entropy=rng, hashfunc=hashlib.sha256)

    f1 = open("/secrets/private_key.pem", "wb")
    f1.write(sk.to_pem())
    f1.close()


    x = sk.privkey.public_key.point.x()
    y = sk.privkey.public_key.point.y()

    x_coord = hex(x)[2:]
    x_coord_len = len(x_coord)
    if(x_coord_len<64) :
        pad_len = 64- x_coord_len
        x_coord = '0'*pad_len + x_coord

    y_coord = hex(y)[2:]
    y_coord_len = len(y_coord)
    if(y_coord_len<64) :
        pad_len = 64- y_coord_len
        y_coord = '0'*pad_len + y_coord

print(x_coord)
print(y_coord)

with open("/secrets/public_key.h", "w") as f2:
            f2.write(f'#define X "{x_coord}"\n')
            f2.write(f'#define Y "{y_coord}"\n')
f2.close()