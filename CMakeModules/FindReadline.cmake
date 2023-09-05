# A CMake module to find a local installation of the Readline library

# Find Readline library
# This module sets the following variables:
#   READLINE_FOUND       - True if Readline is found
#   READLINE_INCLUDE_DIR - Include directories for Readline
#   READLINE_LIBRARIES   - Linker flags for Readline
#   READLINE_VERSION     - Version of Readline

# This module also provides an imported target:
#   Readline::Readline   - Readline library

# Find the pkg-config package for Readline
find_package(PkgConfig REQUIRED)

if (APPLE)
    find_library(READLINE_LIBRARY NAMES readline)
else ()
    pkg_check_modules(READLINE REQUIRED readline)
endif ()
# Set the Readline variables
set(READLINE_FOUND TRUE)
set(READLINE_INCLUDE_DIR ${READLINE_INCLUDE_DIRS})
set(READLINE_LIBRARIES ${READLINE_LDFLAGS})
set(READLINE_VERSION ${READLINE_VERSION})

# Provide imported target for Readline
add_library(Readline::Readline UNKNOWN IMPORTED)
set_target_properties(Readline::Readline PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES "${READLINE_INCLUDE_DIR}"
        INTERFACE_LINK_LIBRARIES "${READLINE_LIBRARIES}"
)

# Find the actual location of the Readline library file
find_library(READLINE_LIBRARY
        NAMES libreadline.so libreadline.dylib libreadline.a
        HINTS ${READLINE_LIBRARY_DIRS}
)

# Set the imported location dynamically
if (READLINE_LIBRARY)
    set_target_properties(Readline::Readline PROPERTIES
            IMPORTED_LOCATION "${READLINE_LIBRARY}"
    )
else ()
    message(FATAL_ERROR "Readline library not found")
endif ()

# Print Readline information
message(STATUS "Found Readline ${READLINE_VERSION}")
message(STATUS "Readline include directories: ${READLINE_INCLUDE_DIR}")
message(STATUS "Readline libraries: ${READLINE_LIBRARIES}")
