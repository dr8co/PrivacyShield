#!/bin/env bash

set -e

# This script is used to build the project on the Ubuntu Jammy (22.04) distribution.
# It is not intended to be used on other distributions, and must be run from the project root.

REQUIRED_PACKAGES=(cmake ninja-build gcc-13 g++-13 clang-17 lldb-17 lld-17 libc++-17-dev libc++abi-17-dev libomp-17-dev libgcrypt20 openssl libreadline8 libsodium23 libsodium-dev)
PARALLELISM_LEVEL=4

function check_root() {
  # Root access is required to install the dependencies.
  if [ "$EUID" -ne 0 ]; then
    echo "Please run as root."
    abort
  fi
}

function check_dependencies() {
  for cmd in wget add-apt-repository cmake; do
    if ! command -v $cmd &>/dev/null; then
      echo "$cmd could not be found"
      exit
    fi
  done
}

function install_dependencies() {
  wget -qO- https://apt.llvm.org/llvm-snapshot.gpg.key | tee /etc/apt/trusted.gpg.d/apt.llvm.org.asc
  add-apt-repository -y "deb http://apt.llvm.org/jammy/ llvm-toolchain-jammy-17 main"
  add-apt-repository -y ppa:ubuntu-toolchain-r/ppa
  apt update

  for package in "${REQUIRED_PACKAGES[@]}"; do
    if ! dpkg -s "$package" >/dev/null 2>&1; then
      apt install -y "$package"
    else
      echo "$package is already installed"
    fi
  done
}

function build_blake3() {
  ./install_blake3.sh clang-17
}

function configure_cmake() {
  cmake -B build -DCMAKE_C_COMPILER=clang-17 -DCMAKE_CXX_COMPILER=clang++-17 -DCMAKE_BUILD_TYPE=Debug -G Ninja
}

function build_project() {
  cmake --build build --config Debug -j "$PARALLELISM_LEVEL"
}

main() {
  trap "echo 'An unexpected error occurred. Program aborted.'" ERR
  check_root
  check_dependencies
  cd "${0%/*}" || abort
  install_dependencies
  build_blake3
  configure_cmake
  build_project
}

main
