#!/bin/env bash

# This script is used to build the project on the Ubuntu Jammy (22.04) distribution.
# It is not intended to be used on other distributions, and must be run from the project root.

# Install the dependencies.
wget -qO- https://apt.llvm.org/llvm-snapshot.gpg.key | sudo tee /etc/apt/trusted.gpg.d/apt.llvm.org.asc
sudo add-apt-repository -y "deb http://apt.llvm.org/jammy/ llvm-toolchain-jammy-17 main"
sudo add-apt-repository -y ppa:ubuntu-toolchain-r/ppa
sudo apt update
sudo apt install -y cmake ninja-build gcc-13 g++-13 clang-17 lldb-17 lld-17 libc++-17-dev \
    libc++abi-17-dev libomp-17-dev libgcrypt20 openssl libreadline8 libsodium23 libsodium-dev

# Build BLAKE3
git clone https://github.com/BLAKE3-team/BLAKE3.git
cd BLAKE3/c || exit
cmake -B build -DCMAKE_C_COMPILER=clang++-17 -G Ninja
sudo cmake --build build --config Release --target install -j 4

# Configure CMake
cd ../../ || exit
cmake -B build -DCMAKE_C_COMPILER=clang-17 -DCMAKE_CXX_COMPILER=clang++-17 -DCMAKE_BUILD_TYPE=Debug -G Ninja

# Build the project
cmake --build build --config Debug -j 4
