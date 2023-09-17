
FROM ubuntu

RUN apt-get update && apt-get upgrade -y && apt-get install --no-install-recommends -y \
    make \
    python3 python3-pip \
    clang \
    binutils-arm-none-eabi \
    gcc-arm-none-eabi libnewlib-arm-none-eabi \
    curl ca-certificates

RUN curl --proto '=https' --tlsv1.3 -sSf https://sh.rustup.rs > rustup_install && chmod +x rustup_install && ./rustup_install -y --profile minimal --target thumbv7em-none-eabi && rm rustup_install
#RUN . ~/.cargo/env && cargo install cbindgen && rm -r ~/.cargo/registry/src ~/.cargo/registry/cache
COPY dummy_proj /tmp/dummy_proj
RUN . ~/.cargo/env && cd /tmp/dummy_proj && cargo fetch

RUN pip install pycryptodomex
