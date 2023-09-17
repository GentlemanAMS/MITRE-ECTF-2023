# 2023 MITRE eCTF Challenge: Protected Automotive Remote Entry Device (PARED)
# By the Michigan State University Spartans
## Spartan State Security Team
## Adrian Self, Udbhav Saxena, Michael Umanskiy, Felipe Marques Allevato
## Faculty Advisor: Dr. Qiben Yan
This repository contains our team's design for MITRE's 2023 Embedded System CTF
(eCTF) - see https://ectf.mitre.org/ for details.

## Design Document
Our design document offers an overview of our design, emphasizing the security measures
in place to protect the secure car and key fob devices. To view the design document, click [Spartans_Design.pdf](Spartans_Design.pdf).

Additionally, we provide a collection of diagrams to offer a
graphical demonstration of the ideas behind each of the key processes,
as well as the natuer of the various objects in the ecosystem.
To view this visualization document, click [Spartans_Visualize.pdf](Spartans_Visualize.pdf).

Our design is further documented in README files, such as
[car/README.md](car/README.md) and [fob/README.md](fob/README.md).
These READMEs give an overview of the functionality of each device type.

Finally, our design is documented via docstrings and code comments to clarify
the intention of each of the functions. Reading the header files (`*.h`)
listed in each README will give helpful insight into how our design works,
before diving into code in the `*.c` files. Macros, structs, and organized
function declarations can be found in the `*.h` files. Docstrings for each
function and code comments for each step of a function can be found in the
`*.c` files.

We hope that this documentation helps you get a clear picture of our design
and how it functions.

## Design Structure
- `car` - source code for building secure car devices
- `deployment` - source code for generating deployment-wide secrets
- `docker_env` - source code for creating docker build environment
- `fob` - source code for building secure key fob devices
- `host_tools` - source code for the host tools

## Running the Design
Our system is designed to integrate with the
[2023 ECTF Tools Repo](https://github.com/mitre-cyber-academy/2023-ectf-tools).
Please see the README in that repository for instructions on how to
build the environment, deploy devices, and interact with deployed devices.