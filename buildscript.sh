#!/bin/env bash

# This script is used to build the project on the Ubuntu Jammy (22.04) distribution.
# It is not intended to be used on other distributions, and must be run from the project root.

# Root access is required to install the dependencies.
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root."
    exit
fi

# Run from this directory
cd "${0%/*}" || exit 1

# Install the dependencies.
wget -qO- https://apt.llvm.org/llvm-snapshot.gpg.key | tee /etc/apt/trusted.gpg.d/apt.llvm.org.asc
add-apt-repository -y "deb http://apt.llvm.org/jammy/ llvm-toolchain-jammy-17 main"
add-apt-repository -y ppa:ubuntu-toolchain-r/ppa
apt update
apt install -y cmake ninja-build gcc-13 g++-13 clang-17 lldb-17 lld-17 libc++-17-dev \
    libc++abi-17-dev libomp-17-dev libgcrypt20 openssl libreadline8 libsodium23 libsodium-dev

# Build BLAKE3
./install_blake3.sh clang-17

# Configure CMake
cmake -B build -DCMAKE_C_COMPILER=clang-17 -DCMAKE_CXX_COMPILER=clang++-17 -DCMAKE_BUILD_TYPE=Debug -G Ninja

# Build the project
cmake --build build --config Debug -j 4
