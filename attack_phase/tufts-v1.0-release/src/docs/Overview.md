# Tufts University | 2023 MITRE eCTF Challenge: Protected Automotive Remote Entry Device (PARED)

## Security alterations/files made:
### /docs contains relevant documentation to help understand our approach
* Unlock Flow.pdf is a flowchart of our unlocking process at a high-level.

### gen_secret.py (car and fob)
* On the car side, a secret key is generated in gen_secret.py. This is done via the secrets library. We create a key that is 128 bits or 16 bytes long, convert it to a byte representation, and put it in hex format so that it can be written to a header file for the car which defines CAR_SECRET, CAR_ID, and PASSWORD. We also make a json files that contains each of the car ids and their respective secrets and passwords. 
* On the fob side, much is similar. We read the json file created by the car's gen_secret.py and once we convert the password to its hex representation, it is written to the fob's header files and defined as PASSWORD. We also defined PAIRED, to tell whether the fob is paired, PAIR_PIN, the pin to pair, and CAR_ID which is the ID of the car the fob is paired to.

### car_rand.c
* This file is dedicated to helping create the 4 random 32-bit integers needed for the pairing challenge. The ISAAC random number generator is used to create the random challenge. 1024 bytes are reserved in the board's EEPROM for the seed, which changes every time the board powers up. Whenever the board is restarted the seed already in the EEPROM is used for the challenge generation and then 1024 bytes are written again for a new seed. We use two different timers on the board in order to create this seed and to prevent replay attacks.

### feature_validation.c
* This files defines a function to help validate features. The tiny-aes and sha256 libraries are used to help aid in this process. Given an array of features (feature package), this function decrypts the features with AES using the CAR_SECRET defined earlier in gen_secret.py. Once each feature is decrypted, we calculate and validate the hash for every feature to determine whether or not they are valid. The last byte of the decrypted feature contains the feature number and the rest is the first 15 bytes of the SHA256 hash of that byte.

### firmware.c (car and fob)
* On the fob side:
    * In pairFob(), instead of strcmp we compare the pin read to the one in the fob_state_ram manually to determine whether the pin is correct. We also add a small delay before sending the board message with the pair_info to let the board fully initialize. We also use strncpy over strcpy.
    * In enableFeature(), we read a message the sizeof the ENABLE_PACKET, rather than just 20 bytes and double check that the message read from the uart is the same size as the packet. We then copy over the enable message's blob to our fob_state_ram and enable it as a new feature which is then declared.
    * In unlockCar(), the fov must request a challenge and when it is received the fob encrypts the challenege and then send it back to the car.
* On the car side:
    * In unlockCar() we check to see whether a challenge is requested. If so, we seed it the first time and then the car creates a challenge for the fob to complete. This challenge is then sent to the fob and when the car gets it back, it decrypts the challenge. If the challenges don't match we sendAckFailure() and if they do we sendAckSuccess() and unlock the car.
    * In startCar() we validate the features then start the car and enable them if they are validated.

