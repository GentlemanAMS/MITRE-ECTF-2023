FROM ubuntu

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get upgrade -y && apt-get install -y \
    make \
    python3.9 \
    python3-pip \
    clang \
    binutils-arm-none-eabi \
    gcc-arm-none-eabi

COPY ./requirements.txt /requirements.txt
RUN pip3 install -r /requirements.txt
