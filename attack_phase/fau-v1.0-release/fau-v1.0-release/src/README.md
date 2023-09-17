# FAU 2023 MITRE eCTF Challenge: Protected Automotive Remote Entry Device (PARED)
This repository contains a secured system for MITRE's 2023 Embedded System CTF
(eCTF) - see https://ectf.mitre.org/ for details. The system is designed by a team at FAU.
## Design Structure
- `car` - source code for building car devices
- `deployment` - source code for generating deployment-wide secrets
- `docker_env` - source code for creating docker build environment
- `fob` - source code for building key fob devices
- `host_tools` - source code for the host tools
## Design Specification
### Security Requirements
**1. A car should only unlock and start when the user has an authentic fob that is paired with the car**

In our design, a car will require a valid 128 bit secret key that is shared with paired fob. First, 256 unique keys for each possible car ID (0-255) are randomly generated at the deployment phase. Then at the build phase, the key associated with the car’s particular ID is then stored in the EEPROM of both the car and the paired fob. If the secret is not the same for both parties, the car will not unlock and will not unlock or start.

**2. Revoking an attacker’s physical access to a fob should also revoke their ability to unlock the associated car** 

A paired fob must store a pairing pin and the unlock key for the corresponding car. These values will be stored securely in EEPROM such that it will be difficult for an attacker with physical access to recover the key.

**3. Observing the communications between a fob and a car while unlocking should not allow an attacker to unlock the car in the future** 

We will secure communication between the paired fob and the car using AES such that it will be very difficult for the attacker to read communications. Both the paired fob and the car will start by AES-encrypting random values using their shared secret as the AES key, and then exchange and AES-decrypt each other’s random value. Now both parties have 2 random values associated with the car and fob. In the next step, they will both do an xor operation on the 2 randoms and retain a new 128 bit value. This creates a secure communication between the paired key and the car using this new random as the shared key for encrypting the unlock message.

![alt text](https://github.com/Ac31415/FAU-Team-2023-ectf-secure-design/blob/main/images/car_fob_secure.png?raw=true)

**4. Having an unpaired fob should not allow an attacker to unlock a car without a corresponding paired fob and pairing PIN** 

A similar secure communication scheme as established in SR3 is done to securely pair an unpaired fob. In addition to the 256 keys associated with the Car IDs, an additional 257th pairing key is generated at deployment, and this key is only sent to paired and unpaired fobs. So the paired fob has 2 keys; one associated with the Car ID it’s meant to unlock, and one that is shared between all authentic fobs, paired and unpaired. The unpaired fob on the other hand only receives the pairing key. We establish the secure communication using AES, and the paired fob sends an AES-encrypted message containing the key associated with its car to the unpaired fob, which then has the task of decrypting this message and obtaining the key. If the unpaired fob does not have the appropriate pairing key, we consider it to not be “authentic”, and it will not be able to decrypt the key it receives from the paired fob correctly, and as such will be able to unlock or start the car, regardless of whether the pairing PIN is known or unknown.

**5. A car owner should not be able to add new features to a fob that did not get packaged by the manufacturer** 

In our design, features are packaged with AES-encrypted Car ID and feature number. The key for encryption is the shared car and pair fob key that is unique for each Car ID. Neither a non-authentic fob or an unpaired fob have access to this key, so they will not be able to decrypt the data correctly and enable the features.

**6. Access to a feature packaged for one car should not allow an attacker to enable the same feature on another car**

Each packaged feature will be associated with a unique Car ID. If one car’s feature was provided to another car’s fob, the other car’s fob will not be able to decrypt the data correctly, preventing the enabling of that feature.
