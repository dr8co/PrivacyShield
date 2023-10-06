#!/bin/env bash

# This script is used to build and install BLAKE3 on Unix-like systems.
# Requires CMake, Ninja, and GCC (or a compatible C compiler) to be installed.

C_COMPILER=gcc

if [ "$1" ]; then
    C_COMPILER="$1"
fi

echo "Compiling BLAKE3 with $C_COMPILER compiler.."

# Root access is required to install BLAKE3 to the system.
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root."
    exit
fi

# Run from this directory
cd "${0%/*}" || exit 1

# Clone the repository
git clone https://github.com/BLAKE3-team/BLAKE3.git

# Build and install BLAKE3
cd BLAKE3/c || echo "Failed to find BLAKE3/c directory" && exit 1
cmake -B build -DCMAKE_C_COMPILER="$C_COMPILER" -G Ninja
cmake --build build --config Release --target install -j 4
