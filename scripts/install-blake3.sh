#!/usr/bin/env bash

# This script is used to build and install BLAKE3 on Unix-like systems.
# Requires CMake, Ninja, and GCC (or a compatible C compiler) to be installed.

# Function to display error message and exit
error_exit() {
    echo "$1" 1>&2
    exit 1
}

# Function to Detect OS and set variables
detect_os() {
    case "$OSTYPE" in
    "linux-gnu"*) CURRENT_OS="linux" ;;
    "darwin"*) CURRENT_OS="macos" ;;
    esac
}

# Function to check root access
check_root() {
    [[ "$CURRENT_OS" == "linux" && "$EUID" -ne 0 ]] && error_exit "This script must be run as root."
}

get_number_of_processors() {
    case "$CURRENT_OS" in
    "linux") NUMBER_OF_PROCESSORS=$(nproc) ;;
    "macos") NUMBER_OF_PROCESSORS=$(sysctl -n hw.ncpu) ;;
    *) NUMBER_OF_PROCESSORS=4 ;;
    esac
}

# Function to download and install BLAKE3
install_blake3() {
  # change to home directory
  cd ~ || error_exit "Failed to change to home directory."

  # Download BLAKE3 and extract to current directory
  wget -qO- https://github.com/BLAKE3-team/BLAKE3/archive/refs/tags/1.5.1.tar.gz | tar -xz -C .

  cd BLAKE3-1.5.1/c || error_exit "Failed to navigate to BLAKE3/c directory."

  cmake -B build -DCMAKE_C_COMPILER="$C_COMPILER" -G Ninja || error_exit "Failed to run cmake."
  get_number_of_processors

  cmake --build build --config Release --target install -j "$NUMBER_OF_PROCESSORS" || error_exit "Failed to build and install."

}

# Function to clone repository
clone_repo() {
    git clone https://github.com/BLAKE3-team/BLAKE3.git || error_exit "Failed to clone BLAKE3 repository."
}

# Function to build and install BLAKE3
build_install() {
    cd BLAKE3/c || error_exit "Failed to navigate to BLAKE3/c directory."
    cmake -B build -DCMAKE_C_COMPILER="$C_COMPILER" -G Ninja || error_exit "Failed to run cmake."
    get_number_of_processors

    cmake --build build --config Release --target install -j "$NUMBER_OF_PROCESSORS" || error_exit "Failed to build and install."

    # Cleanup
    cd ../..
    rm -rf BLAKE3
}

# Set C compiler
C_COMPILER=${1:-gcc}

detect_os
check_root

cd "${0%/*}" || error_exit "Failed to change directory to script location."

echo "Compiling BLAKE3 with $C_COMPILER compiler.."

# Call functions
# clone_repo
# build_install

install_blake3
