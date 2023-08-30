cmake_minimum_required(VERSION 3.25)
project(privacyShield CXX)

set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/CMakeModules")

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS} -Wall -Wextra -Werror -pedantic")

find_package(OpenSSL REQUIRED)
find_package(Sodium REQUIRED)
find_package(Readline REQUIRED)
find_package(Gcrypt REQUIRED)

add_subdirectory(src)
