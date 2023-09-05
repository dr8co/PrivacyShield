cmake_minimum_required(VERSION 3.25)

project(privacyShield
        VERSION 0.1.0
        DESCRIPTION "A suite of tools for privacy and security"
        LANGUAGES CXX)

# If we are not on unix, we cannot build
if(NOT UNIX)
    message(FATAL_ERROR "This project can only be built on unix-like systems")
endif()

# If the user does not specify a build type, default to Release
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Set the path to additional CMake modules
set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/CMakeModules")

# C++23 is required for this project
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Check for compiler warnings and errors
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS} -Wall -Wextra -Werror -pedantic")

# Find dependencies
find_package(OpenSSL REQUIRED)
find_package(Sodium REQUIRED)
find_package(Readline REQUIRED)
find_package(Gcrypt REQUIRED)
find_package(BLAKE3 REQUIRED) # See https://github.com/BLAKE3-team/BLAKE3


add_subdirectory(src)
