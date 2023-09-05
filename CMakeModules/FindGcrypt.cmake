# A CMake module to find a local installation of Gcrypt

# This module sets the following variables:
#   GCRYPT_FOUND       - True if Gcrypt is found
#   GCRYPT_INCLUDE_DIR - Include directories for Gcrypt
#   GCRYPT_LIBRARIES   - Linker flags for Gcrypt
#   GCRYPT_VERSION     - Version of Gcrypt

# This module also provides the imported target Gcrypt::Gcrypt

# Find the pkg-config package for Gcrypt
find_package(PkgConfig REQUIRED)
pkg_check_modules(GCRYPT REQUIRED libgcrypt)

# Set the Gcrypt variables
set(GCRYPT_FOUND TRUE)
set(GCRYPT_INCLUDE_DIR ${GCRYPT_INCLUDE_DIRS})
set(GCRYPT_LIBRARIES ${GCRYPT_LDFLAGS})
set(GCRYPT_VERSION ${GCRYPT_VERSION})

# Provide imported target for Gcrypt
add_library(Gcrypt::Gcrypt UNKNOWN IMPORTED)
set_target_properties(Gcrypt::Gcrypt PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES "${GCRYPT_INCLUDE_DIR}"
        INTERFACE_LINK_LIBRARIES "${GCRYPT_LIBRARIES}"
)

# Find the actual location of the Gcrypt library file
find_library(GCRYPT_LIBRARY
        NAMES libgcrypt.so libgcrypt.dylib libgcrypt.a
        HINTS ${GCRYPT_LIBRARY_DIRS}
)

# Set the imported location dynamically
if (GCRYPT_LIBRARY)
    set_target_properties(Gcrypt::Gcrypt PROPERTIES
            IMPORTED_LOCATION "${GCRYPT_LIBRARY}"
    )
else ()
    message(FATAL_ERROR "Gcrypt library not found")
endif ()

# Print Gcrypt information
message(STATUS "Found Gcrypt ${GCRYPT_VERSION}")
message(STATUS "Gcrypt include directories: ${GCRYPT_INCLUDE_DIR}")
message(STATUS "Gcrypt libraries: ${GCRYPT_LIBRARIES}")
