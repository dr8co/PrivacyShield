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
        LANGUAGES CXX)

set(CMAKE_PROJECT_HOMEPAGE_URL "https://shield.boujee.tech")

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
set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/CMakeModules")

# Additional checks for the Debug build
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS} -Wall -Wextra -Werror -Wpedantic")

# Find the required packages
find_package(OpenSSL REQUIRED)
find_package(Sodium REQUIRED)
find_package(Readline REQUIRED)
find_package(Gcrypt REQUIRED)
find_package(BLAKE3 REQUIRED) # See https://github.com/BLAKE3-team/BLAKE3

# Add the executable target
add_executable(privacyShield)

# Add sources for the target
file(GLOB_RECURSE PRIVACY_SHIELD_SOURCES
        "${CMAKE_SOURCE_DIR}/src/*.cpp")

target_sources(privacyShield PRIVATE ${PRIVACY_SHIELD_SOURCES})

# C++20 Modules
file(GLOB_RECURSE PRIVACY_SHIELD_MODULES
        "${CMAKE_SOURCE_DIR}/src/*.cppm")

target_sources(privacyShield
        PRIVATE
        FILE_SET CXX_MODULES FILES
        ${PRIVACY_SHIELD_MODULES}
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
