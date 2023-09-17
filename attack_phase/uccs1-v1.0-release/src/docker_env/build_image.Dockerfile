FROM ubuntu

# Update package index
RUN apt-get update

# Upgrade system packages
RUN apt-get upgrade -y

# Install required packages
RUN apt-get install -y \
    make \
    python3.9 \
    clang \
    binutils-arm-none-eabi \
    gcc-arm-none-eabi \
    python3-pip


