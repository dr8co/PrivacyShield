cmake_minimum_required(VERSION 3.25)
project(privacyShield)

set(CMAKE_CXX_STANDARD 23)

add_executable(privacyShield main.cpp encryptFiles.cpp main.hpp)
