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
        LANGUAGES C CXX)

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

# Options
include(CMakeDependentOption)
# GCC does not support all sanitizers
cmake_dependent_option(ENABLE_SANITIZERS
        "Enable sanitizers (Ignored if not using Clang compiler)" OFF
        "${CMAKE_CXX_COMPILER_ID} STREQUAL \"Clang\"" OFF)

# Valgrind support
option(VALGRIND_BUILD "Build with Valgrind support" OFF)

# Additional checks for the Debug build
if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_compile_options(
            -Wall
            -Wextra
            -Werror
            -Wpedantic
    )
endif ()

# Add the executable target
add_executable(privacyShield)

# Add sources for the target
target_sources(privacyShield PRIVATE
        src/encryption/encryptDecrypt.cpp
        src/encryption/encryptFiles.cpp
        src/encryption/encryptStrings.cpp
        src/passwordManager/passwordManager.cpp
        src/passwordManager/passwords.cpp
        src/main.cpp
)

# C++20 Modules
target_sources(privacyShield PRIVATE
        FILE_SET CXX_MODULES FILES
        src/duplicateFinder/duplicateFinder.cppm
        src/encryption/cryptoCipher.cppm
        src/encryption/encryption.cppm
        src/fileShredder/fileShredder.cppm
        src/passwordManager/FuzzyMatcher.cppm
        src/passwordManager/passwordManager.cppm
        src/privacyTracks/privacyTracks.cppm
        src/utils/utils.cppm
        src/secureAllocator.cppm
        src/mimallocSTL.cppm
)

# Sanitizers for debugging and testing
# Requires llvm-symbolizer and sanitizer libraries (asan, ubsan, msan, tsan)
if (ENABLE_SANITIZERS)
    # Common flags for all sanitizers
    set(sanitizer_common_flags "-fno-omit-frame-pointer -g -O1")

    # Address, leak, undefined, integer, nullability sanitizers
    set(address_sanitizer_flags "-fsanitize=address,leak,undefined,integer,nullability")

    # Thread sanitizer, cannot be used with address sanitizer
    set(thread_sanitizer_flags "-fsanitize=thread -fPIE")

    # Memory sanitizer, cannot be used with address sanitizer.
    set(memory_sanitizer_flags "-fsanitize=memory -fPIE -fno-optimize-sibling-calls")

    # Add compile options
    add_compile_options(
            "SHELL:${sanitizer_common_flags}"
            "SHELL:${address_sanitizer_flags}"
    )

    # Track mimalloc allocations for AddressSanitizer
    set(MI_TRACK_ASAN ON)

    # Link the enabled sanitizers.
    target_link_libraries(privacyShield PRIVATE asan ubsan)
endif ()

# Valgrind support
if (VALGRIND_BUILD)
    add_compile_options(-g) # Valgrind requires debug symbols
    #    target_link_libraries(privacyShield PRIVATE valgrind)
    set(MI_TRACK_VALGRIND ON)
endif ()

# Find the required packages
find_package(OpenSSL REQUIRED)
find_package(Sodium REQUIRED)
find_package(Gcrypt REQUIRED)

find_package(BLAKE3 QUIET) # See https://github.com/BLAKE3-team/BLAKE3

include(FetchContent)

# Fetch BLAKE3 from GitHub if it is not found
if (NOT TARGET BLAKE3::blake3)
    message(STATUS "BLAKE3 not found. Fetching from GitHub...")

    FetchContent_Declare(
            blake3
            GIT_REPOSITORY https://github.com/BLAKE3-team/BLAKE3.git
            GIT_TAG 454ee5a7c73583cb3060d1464a5d3a4e65f06062
            SOURCE_SUBDIR c
            EXCLUDE_FROM_ALL
    )

    FetchContent_MakeAvailable(blake3)
    target_include_directories(privacyShield PRIVATE "${blake3_SOURCE_DIR}")

endif ()

# Mimalloc allocator
if (NOT TARGET mimalloc-static OR NOT TARGET mimalloc)
    message(STATUS "mimalloc not found. Fetching from GitHub...")

    FetchContent_Declare(
            mimalloc
            GIT_REPOSITORY https://github.com/microsoft/mimalloc.git
            GIT_TAG v2.1.7
            EXCLUDE_FROM_ALL
    )
endif ()

set(MI_BUILD_TESTS OFF) # Do not build tests

FetchContent_MakeAvailable(mimalloc)
target_include_directories(privacyShield PRIVATE "${mimalloc_SOURCE_DIR}/include")
add_library(Mimalloc::mimalloc-static ALIAS mimalloc-static)
add_library(Mimalloc::mimalloc ALIAS mimalloc)

# Fetch Isocline from GitHub
FetchContent_Declare(
        isocline
        GIT_REPOSITORY https://github.com/daanx/isocline.git
        GIT_TAG c9310ae58941559d761fe5d2dd2713d245f18da6
        EXCLUDE_FROM_ALL
)
FetchContent_MakeAvailable(isocline)
target_include_directories(privacyShield PRIVATE "${isocline_SOURCE_DIR}/include")
add_library(ISOCline::isocline ALIAS isocline)

# Link libraries
target_link_libraries(privacyShield PRIVATE
        OpenSSL::Crypto
        Sodium::sodium
        Gcrypt::Gcrypt
        BLAKE3::blake3
        ISOCline::isocline
        Mimalloc::mimalloc-static
)

# Install the binary (optional), with 0755 permissions
include(GNUInstallDirs)
install(TARGETS privacyShield
        DESTINATION ${CMAKE_INSTALL_BINDIR}
        PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
)

include(Packing)
