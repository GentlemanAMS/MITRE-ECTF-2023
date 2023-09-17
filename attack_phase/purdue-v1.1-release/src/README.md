# 2023 MITRE eCTF Challenge: Protected Automotive Remote Entry Device (PARED)

[![Purdue](https://img.shields.io/badge/Boiler-Up-CEB888.svg)](https://purdue.edu)
[![Docs](https://img.shields.io/badge/docs-main-green.svg)](docs)
[![License](https://img.shields.io/badge/license-Apache_2.0-blue.svg)](LICENSE)
[![CI](https://github.com/Purdue-eCTF-2023/PARED/actions/workflows/main.yml/badge.svg)](https://github.com/Purdue-eCTF-2023/PARED/actions/workflows/main.yml)

## Overview

This repository contains the source code for the Purdue's PARED implementation for the 2023 MITRE eCTF.

## Design Structure
- [car](car) - source code for building car devices
- [docker_env](docker_env) - source code for creating docker build environment
- [fob](fob) - source code for building key fob devices
- [host_tools](host_tools) - source code for the host tools

## Documentation :open_book:

Documentation can be found in the [docs](docs) directory.

Technical specifications are located in the [technical specifications file](docs/Technical_Specifications_v1.0.pdf).

API documentation can be found in the [docs/html](docs/html) directory. API documentation can also be generated using the [Doxyfile](Doxyfile).

## Security Features :shield:

### Car Unlock :car::unlock:

Car and paired fob are provisioned with symmetric keys (`K`).
To prevent unpaired fobs from unlocking the car, a challenge-response protocol is used.
The car sends a message encrypted with `K` to the fob which is trying to unlock the car.
To unlock the car, the fob must decrypt the message and send it back to the car.

### Fob Pairing :key::key:

To prevent an unauthorized user from using a paired fob to pair an unpaired fob, the pairing pin is required to pair the unpaired fob.
If correct pairing pin is sent to the paired fob, then the paired fob will send the symmetric key to the unpaired fob.
To prevent brute-force attacks on the pairing PIN, the paired fob goes into a sleep state when a brute-force attack is detected.

### Enabling Features :wrench::gear:

To prevent an unauthorized user from enabling features on the car, each feature is protected by a password that is unique to each car and feature.
To enable a feature, the user must provide the correct feature password to the car.

## Members :busts_in_silhouette:

**Students:** Siddharth Muralee, Ashwin Nambiar, Gisu Yeo, Shashank Sharma, Jayashree Srinivasan, Akul Pillai, Aditya Vardhan, Ayushi Sharma, Connor Glosner, Abhishek Reddypalle, Pashcal Amusuo, Bo-Shiun Yen, Alan Chung Ma, Han Dai, Hongwei Wu, Muhammad Ibrahim, Jacob White, Arun Kumar, Albert Yu, Naveen Kusumanchi, Garvit.

**Advisors:** Dr. Antonio Bianchi, Dr. Aravind Machiry
