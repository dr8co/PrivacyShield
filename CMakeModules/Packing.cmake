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
# A CMake module to generate a package for Privacy Shield
#

# Set the CPack variables
set(CPACK_PACKAGE_NAME "PrivacyShield")
set(CPACK_PACKAGE_VENDOR "Ian Duncan")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "A suite of tools for privacy and security")
set(CPACK_PACKAGE_VERSION "2.0.0")
set(CPACK_PACKAGE_CONTACT "dr8co@duck.com")

SET(CPACK_OUTPUT_FILE_PREFIX "${CMAKE_SOURCE_DIR}/Packages")

set(CPACK_SOURCE_IGNORE_FILES
        /.git
        /.idea
        /.github
        /.vscode
        /.cache
        /build
        /cmake-build-*
        /CMakeFiles
        /CMakeScripts
        /CMakeModules
        /CMakeLists.txt.user
        /CMakeCache.txt
        /CTestTestfile.cmake
        /Makefile
        /Makefile.in
        /CPackConfig.cmake
        /CPackSourceConfig.cmake
        /CPackSourceConfig.cmake
        /CPack
)

set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
set(CPACK_RESOURCE_FILE_README "${CMAKE_CURRENT_SOURCE_DIR}/README.md")

set(CPACK_DEBIAN_FILE_NAME DEB-DEFAULT)
set(CPACK_RPM_FILE_NAME RPM-DEFAULT)

# Set the type of installer you want to generate
set(CPACK_GENERATOR "DEB;RPM")

# Strip the executable from debug symbols
set(CPACK_STRIP_FILES YES)

# Set the package dependencies
set(CPACK_DEBIAN_PACKAGE_DEPENDS "libc6 (>= 2.35), libstdc++6 (>= 13.2.0), openssl (>= 3.0.0), libsodium23 (>= 1.0.18), libreadline8 (>= 8.0), libgcrypt20 (>= 1.10.0), libgcc-s1 (>= 13.2.0)")
set(CPACK_RPM_PACKAGE_REQUIRES "libc6 >= 2.35, libstdc++ >= 13.2.0, openssl >= 3.0.0, libsodium >= 1.0.18, readline >= 8.0, libgcrypt >= 1.10.0, libgcc >= 13.2.0")

set(CPACK_RPM_PACKAGE_LICENSE "GPLv3")

# Set the section of the package
set(CPACK_DEBIAN_PACKAGE_SECTION "utils")

# Use the resource file for the license
set(CPACK_DMG_SLA_USE_RESOURCE_FILE_LICENSE ON)

set(CPACK_PACKAGE_CHECKSUM "SHA256")

include(CPack)