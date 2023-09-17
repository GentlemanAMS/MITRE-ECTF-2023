# eCTF 2023 UNewHaven Protocol
This document gives an overview of the protocol used in this eCTF 2023 competition.

## Frame
Each message will be packed in a frame. Each frame will have the following format (exceptions are noted):

| Packet Size (1 byte) | Encrypted Data ( n bytes in 16 byte chunks) | CRC (2 bytes)

- The packet size is bounded between 3 and 80 bytes
- The packet size includes the CRC
- Encrypted Data will be in 16 byte chunks except where specified
- The encrypted data is ALWAYS encrypted with the shared AES key (more on that later) except where specified
- Unused data shall be padded with random data

## Sizes
- AES Block Size: 16 bytes
- AES IV Size: 128 bits (16 bytes)
- AES Key Size: 192 bits (24 bytes)
- ECDH Size: 192 bytes (24 bytes)
- ECDH Public Key: 48 bytes

## Secrets
The following secrets will be flashed per fob:
- **Feature AES Key (24 bytes)**: A key to decryption a feature data
- **Pin AES Key (24 bytes)**: A key that is used to encrypt a pin, which is how it's stored internally to the fob

The following secrets will be flashed per car and fob pair:
- **Car Unlock Secret (16 bytes)**: A secret key that is used to authenticate a fob

## Packet Definition
Here are the different data packets possible in this system.
Shown is only the data porting of a frame

| Name                              | Data Structure                                                    | Notes                                                                     |
|-----------------------------------|-------------------------------------------------------------------|---------------------------------------------------------------------------|
| Establish Channel                 | `0xAB` > ECHD Public Key (48 bytes) > AES Start IV (16 bytes)     | The data is not encrypted, and the encrypted data format is not followed  |
| Establish Channel Return          | `0xE0` > ECHD Public Key (48 bytes)                               | The data is not encrypted, and the encrypted data format is not followed  |
| Set Paired fob in Pairing Mode    | `0x4D`                                                            |                                                                           |
| Set Unpaired Fob to Pair          | `0x50` > Hashed Pin (16 bytes)                                    | This call will have the unpaired fob start communication with paired fob  |
| Get Secret from Paired            | `0x47` > Encrypted Pin (16 bytes)                                 |                                                                           |
| Pairing Done                      | `0x48`                                                            |                                                                           |
| Return Secret from Paired         | `0x52` > Car Unlock Secret (16 bytes)                             |                                                                           |
| ACK                               | `0x41`                                                            |                                                                           |
| NACK                              | `0xAA`                                                            |                                                                           |
| Enable Feature                    | `0x45` > Encrypted Feature data (32 bytes)                        |                                                                           |
| Unlock Car                        | `0x55` > Car Unlock Secret (16 bytes) > Feature Bitfield (1 byte) |                                                                           |
| Unlocked Car Message              | _64-bits + (64-bits * feature_enabled)_                           | The data format is not followed at all for this packet                    |

## Pin
The pin, a 6-digit string, will be taken and hashed with BLAKE2 which will be called "Hashed Pin".

### Encrypted Pin
When transmitting the pin between fobs, the pin will be further encrypted with a pre-set decryption key.

## Feature Data
The un-encrypted feature data is defined as follows:

Random Bytes (15 bytes) > Car Unlock Secret (16 bytes) > Feature Number (1 byte, 0 to 2)

This data is then encrypted with a Feature Encryption Key that is unique and stored per-fob

## Transactions
The following section describes the different possible transactions

Here are the naming abbreviation:
- U -> Unpaired Fob
- P -> Paired Fob
- H -> Host

### Pair Fob Process
```
|---|     |---|
|   |<--->| P |<---\
|   |     |---|    |
| H |              |
|   |     |---|    |
|   |<--->| U |<---/
|---|     |---|
```
#### Packet Sequence
1.  H -> P => `Establish Channel`
2.  P -> H => `Establish Channel Return`
3.  H -> P => `Set Paired fob in Pairing Mode`
4.  P -> H => `ACK`
5.  H -> U => `Establish Channel`
6.  U -> H => `Establish Channel Return`
7.  H -> U => `Set Unpaired Fob to Pair`
8.  U -> H => `ACK`
9.  U -> P => `Establish Channel`
10. P -> U => `Establish Channel Return`
11. U -> P => `Get Secret from Paired`
12. P -> U => `Return Secret from Paired`
13. U -> H => `Pairing Done`

## Enable Feature
```
|---|     |---|
| H |<--->| P |
|---|     |---|
```
#### Packet Sequence
1.  H -> P => `Establish Channel`
2.  P -> H => `Establish Channel Return`
3.  H -> P => `Enable Feature`
4.  P -> H => `ACK`

## Unlock Car
```
|---|     |---|     |---|
| H |<--->| C |<--->| P |
|---|     |---|     |---|
```
#### Packet Sequence
1. P -> C => `Establish Channel`
2. C -> P => `Establish Channel Return`
3. P -> C => `Unlock Car`
4. C -> H => `Unlocked Car Message`
