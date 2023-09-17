
FROM ubuntu

RUN apt-get update && apt-get upgrade -y && apt-get install -y \
    curl

RUN curl -sSf https://sh.rustup.rs -o rustup-init.sh && chmod +x rustup-init.sh && ./rustup-init.sh -y

RUN apt-get install -y \
    make \
    python3.9 \
    python3-pip \
    clang \
    binutils-arm-none-eabi \
    gcc-arm-none-eabi \
    llvm \
    clang \
    libc6-dev-i386

# RUN $HOME/.cargo/bin/

RUN $HOME/.cargo/bin/cargo install cargo-make

RUN $HOME/.cargo/bin/rustup target add thumbv7em-none-eabihf

#RUN python3 -m pip install --upgrade pip
RUN pip3 install pycryptodome pynacl