#!/usr/bin/env bash

# Run from this directory
cd "$(dirname "$0")" || (echo "Running from $(pwd)" && exit 1)

# Include the build functions
. ./build-functions.sh

# Root access is required to install the dependencies.
check_root

# Build and install GCC 14
build_install_gcc_14

# Install dependencies
apt remove -y --purge --auto-remove llvm-16-dev clang-16 clang-tidy-16 clang-format-16 lld-16 libc++-16-dev libc++abi-16-dev
apt update && apt install -y software-properties-common wget unzip build-essential openssl libsodium23 libsodium-dev libgcrypt20-dev
wget -qO- https://apt.llvm.org/llvm-snapshot.gpg.key | tee /etc/apt/trusted.gpg.d/apt.llvm.org.asc
add-apt-repository -y "deb http://apt.llvm.org/bookworm/ llvm-toolchain-bookworm-18 main"
apt update
export NEEDRESTART_SUSPEND=1
apt install -y llvm-18-dev clang-18 lldb-18 lld-18 libc++-18-dev libc++abi-18-dev libllvmlibc-18-dev clang-tools-18 clang-tidy-18 clang-format-18

for f in /usr/lib/llvm-18/bin/*; do
  ln -sf "$f" /usr/bin;
done

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

echo "Ninja: $(ninja --version), CMake: $(cmake --version)"

# Build and install BLAKE3
build_blake3

# Configure CMake
cd .. || abort
/usr/local/bin/cmake -S . -B build -DCMAKE_C_COMPILER=clang-18 -DCMAKE_CXX_COMPILER=clang++-18 -DCMAKE_BUILD_TYPE=Debug -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -G Ninja

