cmake_minimum_required(VERSION 3.25)
project(privacyShield)

set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/CMakeModules")

set(CMAKE_CXX_STANDARD 23)

find_package(OpenSSL REQUIRED)
find_package(Sodium REQUIRED)
find_package(CryptoPP REQUIRED)

add_executable(privacyShield main.cpp encryptFiles.cpp main.hpp duplicatesFinder.cpp)

target_link_libraries(privacyShield ssl sodium crypto)
