
FROM ubuntu

RUN apt-get update && apt-get upgrade -y && apt-get install -y \
    make \
    python3.10 \
    python3-pip \
    clang \
    binutils-arm-none-eabi \
    gcc-arm-none-eabi

RUN pip3 install pymonocypher
