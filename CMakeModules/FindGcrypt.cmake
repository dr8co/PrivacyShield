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
#
#################################################################################
#
# A CMake module to find a local installation of Gcrypt and Gpg-error

# This module sets the following variables for Gcrypt:
#   GCRYPT_FOUND       - True if Gcrypt is found
#   GCRYPT_INCLUDE_DIR - Include directories for Gcrypt
#   GCRYPT_LIBRARIES   - Linker flags for Gcrypt
#   GCRYPT_VERSION     - Version of Gcrypt

# This module also sets the following variables for Gpg-error:
#   GPG_ERROR_FOUND       - True if Gpg-error is found
#   GPG_ERROR_INCLUDE_DIR - Include directories for Gpg-error
#   GPG_ERROR_LIBRARIES   - Linker flags for Gpg-error
#   GPG_ERROR_VERSION     - Version of Gpg-error

# This module also provides the imported targets Gcrypt::Gcrypt and Gcrypt::Gpg_error

# Find the pkg-config package for Gcrypt & Gpg-error
find_package(PkgConfig REQUIRED)
pkg_check_modules(GCRYPT REQUIRED libgcrypt)
pkg_check_modules(GPG_ERROR gpg-error)

# Set the Gcrypt variables
set(GCRYPT_FOUND TRUE)
set(GCRYPT_INCLUDE_DIR ${GCRYPT_INCLUDE_DIRS})
set(GCRYPT_LIBRARIES ${GCRYPT_LDFLAGS})
set(GCRYPT_VERSION ${GCRYPT_VERSION})

# Provide imported target for Gcrypt
add_library(Gcrypt::Gcrypt UNKNOWN IMPORTED)

set_target_properties(Gcrypt::Gcrypt PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES "${GCRYPT_INCLUDE_DIR}"
        INTERFACE_LINK_LIBRARIES "${GCRYPT_LIBRARIES}")

# Set the Gpg-error variables
add_library(Gcrypt::Gpg_error UNKNOWN IMPORTED)
set_target_properties(Gcrypt::Gpg_error PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES "${GPG_ERROR_INCLUDE_DIR}"
        INTERFACE_LINK_LIBRARIES "${GPG_ERROR_LIBRARIES}")

# Find the actual location of the Gcrypt library file
find_library(GCRYPT_LIBRARY
        NAMES libgcrypt.so libgcrypt.dylib libgcrypt.a
        HINTS ${GCRYPT_LIBRARY_DIRS})

# Find the actual location of the Gpg-error library file
find_library(GPG_ERROR_LIBRARY
        NAMES libgpg-error.so libgpg-error.dylib libgpg-error.a
        HINTS ${GPG_ERROR_LIBRARY_DIRS})

# Set the imported location dynamically
if (GCRYPT_LIBRARY)
    set_target_properties(Gcrypt::Gcrypt PROPERTIES
            IMPORTED_LOCATION "${GCRYPT_LIBRARY}")
else ()
    message(FATAL_ERROR "Gcrypt library not found")
endif ()


# Set the imported location dynamically
if (GPG_ERROR_LIBRARY)
    set_target_properties(Gcrypt::Gpg_error PROPERTIES
            IMPORTED_LOCATION "${GPG_ERROR_LIBRARY}")
else ()
    message(FATAL_ERROR "Gpg-error library not found")
endif ()

# Print Gcrypt information
message(STATUS "Found Gcrypt ${GCRYPT_VERSION}")
message(STATUS "Gcrypt include directories: ${GCRYPT_INCLUDE_DIR}")
message(STATUS "Gcrypt libraries: ${GCRYPT_LIBRARIES}")

# Print Gpg-error information
message(STATUS "Found Gpg-error ${GPG_ERROR_VERSION}")
message(STATUS "Gpg-error include directories: ${GPG_ERROR_INCLUDE_DIR}")
message(STATUS "Gpg-error libraries: ${GPG_ERROR_LIBRARIES}")
