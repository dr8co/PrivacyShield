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

cmake_minimum_required(VERSION 3.25)

project(privacyShield
        VERSION 1.0.0
        DESCRIPTION "A suite of tools for privacy and security"
        LANGUAGES CXX)

# If the user is not on a unix-like system, fail the build
if (NOT UNIX)
    message(FATAL_ERROR "This project is only supported on unix-like systems.")
endif ()

# If the user does not specify a build type, default to Release
if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif ()

# Set the path to additional CMake modules
set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/CMakeModules")

# C++23 is required for this project
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Check for extra compiler warnings and errors in debug config
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS} -Wall -Wextra -Werror -pedantic")

# Find dependencies
find_package(OpenSSL REQUIRED)
find_package(Sodium REQUIRED)
find_package(Readline REQUIRED)
find_package(Gcrypt REQUIRED)
find_package(BLAKE3 REQUIRED) # See https://github.com/BLAKE3-team/BLAKE3

# Add the executable target
add_executable(privacyShield)

# Add sources for the target
file(GLOB_RECURSE PRIVACY_SHIELD_SOURCES
        "${CMAKE_SOURCE_DIR}/src/*.cpp"
        "${CMAKE_SOURCE_DIR}/src/*.hpp")

target_sources(privacyShield PRIVATE ${PRIVACY_SHIELD_SOURCES})

# Link dependencies
target_link_libraries(privacyShield
        PRIVATE OpenSSL::Crypto
        PRIVATE Readline::Readline
        PRIVATE Sodium::sodium
        PRIVATE Gcrypt::Gcrypt
        PRIVATE BLAKE3::blake3)

# Install the binary (optional)
install(TARGETS privacyShield
        DESTINATION bin
        PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
)
