# TEAM UCCS2 SUBMISSION
# 2023 MITRE eCTF Challenge: Protected Automotive Remote Entry Device (PARED)

Basic SHA256 implementation in the unlockCar() for both car and key fob firmware. The password and car id are both concatenated into a single hash where the fob is sending that hash to car (are doing the same hashing) for verification before unlocking the car.

## Changes Made
- SHA256.h & SHA256.c - source code SHA256 algorithm (special thanks to Brad Conte and it's code from GitHub)
- #include 'SHA256.h' - In both car and fob firmware 
- Car 'firmware.c' - New function name 'SHA256_test()' where this is called during the validation process in unlockCar. The 'SHA256_test()' is being 'memcmp' with the message.buffer in which it is a structure created in car firmware in order to receive the buffer from key fob. 
- Fob 'firmware.c' - In the 'unlockCar()' function, I have used text 1 & 2 to store the password and car id that is in a paired fob while concatenate both password and car id into another text called text 3. Using SHA256.h and SHA256.c, I am able to initialize, update and produce final hash that will consistently update BYTE buf. Using the original 'MESSAGE PACKET', I am able to use SHA256 block size and declare into message length and send the buf via 'message.buffer' variable. On the car side, the car will also be producing the same hash for verification in the car's unlockCar() function.

## Big Ideas and Future Implementation
- Instead of sending plaintext value, using hash gives additional security for validation. However, the initial plan was to use a counter that increases each time after a successful transaction that will give some entropy. This way, attackers will not be getting the same hash via communication. Due to issues with memory management, this is not implemented.
- If counter would not be an issue, then another method that can be implemented simultaneously would be some nonce. The nonce can work along with counter and can be randomly generated in each session. However, this would give some communication overhead that might effect performance. With 1 second requirement for unlocking, this can be done if each time a new random nonce is generated rather than having the devices generate n amount of nonce for the other device to validate. Furthermore, there would be more considerations when it comes to more unpaired fob getting paired where synchronization would be another challenge.
- Implementation of AES can be possible. While this seems redundant if we believe hashing would work correctly. However, providing AES encryption would also address a different attack vector while provide additional security in different areas of communication transmission. Especially if more acknowledgement (ack()) are needed due to ideas (hashing counter and nonce) above to happen between the car and key fob.


Team members: Ken L.(Team Lead), Sourav P., Arijet S., Mark V.
Thank you team members for contributing your time, ideas, effort to this design and implementation. - Ken L.
