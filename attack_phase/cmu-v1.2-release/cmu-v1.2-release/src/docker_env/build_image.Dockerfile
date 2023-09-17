FROM ubuntu

RUN apt-get update && apt-get upgrade -y && apt-get install -y \
    make \
    python3.9 \
    python3-pip \
    llvm-13 \
    lld-13 \
    clang-13 \
    binutils-arm-none-eabi \
    gcc-arm-none-eabi \
    git \
    cmake

COPY libclang_rt.builtins-armv7em.a /home/libclang_rt.builtins-armv7em.a 

RUN pip3 install pymonocypher==3.1.3.1
