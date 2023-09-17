
FROM ubuntu

RUN apt-get update && apt-get upgrade -y && apt-get install -y \
    make \
    python3.9 \
    # python3.9-distutils \
    clang \
    curl \
    binutils-arm-none-eabi \
    gcc-arm-none-eabi

RUN apt-get install -y python3-pip
# RUN curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py && python3 get-pip.py
    
RUN pip3 install cryptography