#!/usr/bin/env bash

# Run from this directory
cd "${0%/*}" || abort

# Include the build functions
. ./build-functions.sh

# Root access is required to install the dependencies.
check_root

# Check for required commands
check_dependencies

# Install dependencies
install_dependencies

echo "Ninja: $(ninja --version), CMake: $(cmake --version)"

# Build and install BLAKE3
build_blake3

# Configure CMake
cd .. || abort
configure_cmake

# Build the project
build_project