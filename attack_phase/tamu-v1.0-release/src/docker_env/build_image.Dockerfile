FROM rustlang/rust:nightly-buster-slim as base

ENV CARGO_UNSTABLE_SPARSE_REGISTRY=true
RUN rustup toolchain install nightly-2023-02-08
RUN rustup default nightly-2023-02-08
RUN rustup target add thumbv7em-none-eabi
RUN rustup component add llvm-tools-preview rust-src
RUN cargo install cargo-binutils

RUN apt-get update && apt-get upgrade -y && apt-get install -y \
    make \
    python3
    # clang \
    # binutils-arm-none-eabi \
    # gcc-arm-none-eabi

COPY gen_eeprom ./gen_eeprom/
COPY pared_core ./pared_core/
COPY eeprom_layout ./eeprom_layout/
COPY host_tools ./host_tools/
RUN cargo install --path gen_eeprom
