
FROM ubuntu

RUN apt-get update && apt-get upgrade -y && apt-get install -y \
    make \
    python3.9 \
    clang \
    binutils-arm-none-eabi \
    gcc-arm-none-eabi \
    python3-pycryptodome \
    python3-pip

RUN pip install pycryptodome crcmod cryptography
