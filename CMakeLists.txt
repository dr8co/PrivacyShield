# Privacy Shield: A Suite of Tools Designed to Facilitate Privacy Management.
# Copyright (C) 2024  Ian Duncan <dr8co@duck.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see https://www.gnu.org/licenses.

# CMake 3.28+ is required for C++20 modules
cmake_minimum_required(VERSION 3.28)

project(privacyShield
        VERSION 2.5.0
        DESCRIPTION "A suite of tools for privacy and security"
        HOMEPAGE_URL "https://shield.iandee.tech"
        LANGUAGES CXX)

# C++23 support is required for this project
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# If the target system is not UNIX, fail the build
if (NOT UNIX)
    message(FATAL_ERROR "This project is only supported on unix-like systems.")
endif ()

# If the build type is not specified, default to Release
if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif ()

# Set the path to additional CMake modules
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/CMakeModules")

# Additional checks for the Debug build
if (CMAKE_C_COMPILER_ID MATCHES "GNU|Clang|AppleClang")
    if (CMAKE_BUILD_TYPE STREQUAL "Debug")
        add_compile_options(
                -Wall
                -Wextra
                -Werror
                -Wpedantic
        )
    endif ()
endif ()

# Find the required packages
find_package(OpenSSL REQUIRED)
find_package(Sodium REQUIRED)
find_package(Readline REQUIRED)
find_package(Gcrypt REQUIRED)
find_package(BLAKE3 REQUIRED) # See https://github.com/BLAKE3-team/BLAKE3

# Add the executable target
add_executable(privacyShield)

# Add sources for the target
target_sources(privacyShield PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/src/encryption/encryptDecrypt.cpp"
        "${CMAKE_CURRENT_SOURCE_DIR}/src/encryption/encryptFiles.cpp"
        "${CMAKE_CURRENT_SOURCE_DIR}/src/encryption/encryptStrings.cpp"
        "${CMAKE_CURRENT_SOURCE_DIR}/src/passwordManager/passwordManager.cpp"
        "${CMAKE_CURRENT_SOURCE_DIR}/src/passwordManager/passwords.cpp"
        "${CMAKE_CURRENT_SOURCE_DIR}/src/utils/utils.cpp"
        "${CMAKE_CURRENT_SOURCE_DIR}/src/main.cpp"
)

# C++20 Modules
target_sources(privacyShield PRIVATE
        FILE_SET CXX_MODULES FILES
        "${CMAKE_CURRENT_SOURCE_DIR}/src/duplicateFinder/duplicateFinder.cppm"
        "${CMAKE_CURRENT_SOURCE_DIR}/src/encryption/cryptoCipher.cppm"
        "${CMAKE_CURRENT_SOURCE_DIR}/src/encryption/encryption.cppm"
        "${CMAKE_CURRENT_SOURCE_DIR}/src/fileShredder/fileShredder.cppm"
        "${CMAKE_CURRENT_SOURCE_DIR}/src/passwordManager/FuzzyMatcher.cppm"
        "${CMAKE_CURRENT_SOURCE_DIR}/src/passwordManager/passwordManager.cppm"
        "${CMAKE_CURRENT_SOURCE_DIR}/src/privacyTracks/privacyTracks.cppm"
        "${CMAKE_CURRENT_SOURCE_DIR}/src/utils/utils.cppm"
        "${CMAKE_CURRENT_SOURCE_DIR}/src/secureAllocator.cppm"
)

# Link libraries
target_link_libraries(privacyShield
        PRIVATE OpenSSL::Crypto
        PRIVATE Readline::Readline
        PRIVATE Sodium::sodium
        PRIVATE Gcrypt::Gcrypt
        PRIVATE BLAKE3::blake3)

# Install the binary (optional), with 0755 permissions
include(GNUInstallDirs)
install(TARGETS privacyShield
        DESTINATION ${CMAKE_INSTALL_BINDIR}
        PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
)

include(Packing)
