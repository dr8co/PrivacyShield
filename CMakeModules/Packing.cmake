# Set the CPack variables
set(CPACK_PACKAGE_NAME "PrivacyShield")
set(CPACK_PACKAGE_VENDOR "Ian Duncan")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "A suite of tools for privacy and security")
set(CPACK_PACKAGE_VERSION "1.0.0")
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

set(CPACK_PACKAGE_CHECKSUM "SHA512")

include(CPack)