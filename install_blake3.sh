#!/bin/env bash

# This script is used to build and install BLAKE3 on Unix-like systems.
# Requires CMake, Ninja, and GCC (or a compatible C compiler) to be installed.

# Root access is required to install BLAKE3 to the system.
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root."
    exit
fi

# Clone the repository
git clone https://github.com/BLAKE3-team/BLAKE3.git

# Build and install BLAKE3
cd BLAKE3/c || echo "Failed to find BLAKE3/c directory" && exit
cmake -B build -DCMAKE_C_COMPILER=gcc -G Ninja
cmake --build build --config Release --target install -j 4
