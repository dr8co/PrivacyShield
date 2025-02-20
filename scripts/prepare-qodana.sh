#!/usr/bin/env bash

CLANG_VER="19"
OLD_CLANG_VER="16"
CMAKE_VER="3.31.5"
NINJA_VER="1.12.1"

# Run from this directory
cd "$(dirname "$0")" || (echo "Running from $(pwd)" && exit 1)

# Include the build functions
. ./build-functions.sh

# Root access is required to install the dependencies.
check_root

# Build and install GCC 14
curl -LSso build-gcc.sh https://gcc.optimizethis.net
bash build-gcc.sh

# Install dependencies
apt remove -y --purge --auto-remove llvm-${OLD_CLANG_VER}-dev clang-${OLD_CLANG_VER} clang-tidy-${OLD_CLANG_VER} clang-format-${OLD_CLANG_VER} lld-${OLD_CLANG_VER} libc++-${OLD_CLANG_VER}-dev libc++abi-${OLD_CLANG_VER}-dev

apt update && apt install -y software-properties-common wget unzip build-essential openssl libsodium23 libsodium-dev libgcrypt20-dev

wget -qO- https://apt.llvm.org/llvm-snapshot.gpg.key | tee /etc/apt/trusted.gpg.d/apt.llvm.org.asc
add-apt-repository -y "deb http://apt.llvm.org/bookworm/ llvm-toolchain-bookworm-${CLANG_VER} main"

apt update
export NEEDRESTART_SUSPEND=1
apt install -y llvm-${CLANG_VER}-dev clang-${CLANG_VER} lldb-${CLANG_VER} lld-${CLANG_VER} libc++-${CLANG_VER}-dev libc++abi-${CLANG_VER}-dev libllvmlibc-${CLANG_VER}-dev clang-tools-${CLANG_VER} clang-tidy-${CLANG_VER} clang-format-${CLANG_VER}

for f in "/usr/lib/llvm-${CLANG_VER}/bin/"*; do
  ln -sf "$f" /usr/bin;
done

# Install CMake
if dpkg -s "cmake" >/dev/null 2>&1; then
  apt remove -y --purge --auto-remove cmake
fi

wget -qO- "https://github.com/Kitware/CMake/releases/download/v${CMAKE_VER}/cmake-${CMAKE_VER}-linux-x86_64.tar.gz" | tar --strip-components=1 -xz -C /usr/local

# Install Ninja
if dpkg -s "ninja-build" >/dev/null 2>&1; then
  apt remove -y --purge --auto-remove ninja-build
fi

wget -q "https://github.com/ninja-build/ninja/releases/download/v${NINJA_VER}/ninja-linux.zip"
unzip ninja-linux.zip -d /usr/local/bin

echo "Ninja: $(ninja --version), CMake: $(cmake --version)"

# Configure CMake
cd .. || echo "Failed to navigate to parent directory" && exit 1
/usr/local/bin/cmake -S . -B build -DCMAKE_C_COMPILER=clang-${CLANG_VER} -DCMAKE_CXX_COMPILER=clang++-${CLANG_VER} -DCMAKE_BUILD_TYPE=Debug -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -G Ninja

