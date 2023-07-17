cmake_minimum_required(VERSION 3.25)
project(privacyShield)

set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/CMakeModules")

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS_DEBUG "-Wall -Wextra -Werror -pedantic")

find_package(OpenSSL REQUIRED)
find_package(Sodium REQUIRED)
find_package(CryptoPP REQUIRED)
find_package(BZip2 REQUIRED)

add_subdirectory(src)
