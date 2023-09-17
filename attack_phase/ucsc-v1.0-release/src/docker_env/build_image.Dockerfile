FROM archlinux:latest AS base
RUN pacman -Sy
RUN pacman -S --noconfirm rustup
RUN rustup default nightly
RUN rustup target add thumbv7em-none-eabihf
RUN pacman -S --noconfirm openocd arm-none-eabi-gdb arm-none-eabi-gcc arm-none-eabi-binutils gcc make git usbutils net-tools
ADD ./ /docker_env
