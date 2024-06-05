#!/usr/bin/env bash

# Run from this directory
cd "$(dirname "$0")" || (echo "Running from $(pwd)" && exit 1)

# Include the build functions
. ./build-functions.sh

# Root access is required to install the dependencies.
check_root

# Install dependencies
install_dependencies

echo "Ninja: $(ninja --version), CMake: $(cmake --version)"

# Build and install BLAKE3
build_blake3

# Configure CMake
cd .. || abort
/usr/local/bin/cmake -S . -B build -DCMAKE_C_COMPILER=clang-18 -DCMAKE_CXX_COMPILER=clang++-18 -DCMAKE_BUILD_TYPE=Debug -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -G Ninja

