#!/usr/bin/env bash

set -e

# This script is used to build the project on the Ubuntu Noble (24.04) distribution.
# It is not intended to be used on other distributions, and must be run from the project root.

PARALLELISM_LEVEL=4

function check_root() {
  # Root access is required to install the dependencies.
  if [ "$EUID" -ne 0 ]; then
    echo "Please run as root."
    abort
  fi
}

function install_dependencies() {
#  wget -qO- https://apt.llvm.org/llvm-snapshot.gpg.key | tee /etc/apt/trusted.gpg.d/apt.llvm.org.asc
#  add-apt-repository -y "deb http://apt.llvm.org/jammy/ llvm-toolchain-jammy-18 main"
#  add-apt-repository -y ppa:ubuntu-toolchain-r/ppa
  apt update
  export NEEDRESTART_SUSPEND=1
  apt install -y wget unzip gcc-14 g++-14 clang-18 lldb-18 lld-18 libc++-18-dev libc++abi-18-dev libllvmlibc-18-dev clang-tools-18 libgcrypt20-dev openssl libreadline8 libreadline-dev libsodium23 libsodium-dev

  # Install CMake 3.29.3
  if dpkg -s "cmake" >/dev/null 2>&1; then
    apt remove -y --purge --auto-remove cmake
  fi

  wget -qO- "https://github.com/Kitware/CMake/releases/download/v3.29.3/cmake-3.29.3-linux-x86_64.tar.gz" | tar --strip-components=1 -xz -C /usr/local

  # Install Ninja 1.12
  if dpkg -s "ninja-build" >/dev/null 2>&1; then
    apt remove -y --purge --auto-remove ninja-build
  fi

  wget -q "https://github.com/ninja-build/ninja/releases/download/v1.12.1/ninja-linux.zip"
  unzip ninja-linux.zip -d /usr/local/bin
}

function build_blake3() {
  ./install-blake3.sh clang-18
}

function configure_cmake() {
  cmake -B build -DCMAKE_C_COMPILER=clang-18 -DCMAKE_CXX_COMPILER=clang++-18 -DCMAKE_BUILD_TYPE=Debug -G Ninja
}

function build_project() {
  cmake --build build --config Debug -j "$PARALLELISM_LEVEL"
}

trap "echo 'An unexpected error occurred. Program aborted.'" ERR
