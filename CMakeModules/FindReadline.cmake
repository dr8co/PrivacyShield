# A CMake module to find a local installation of the Readline library

# Find Readline library
# This module sets the following variables:
#   READLINE_FOUND       - True if Readline is found
#   READLINE_INCLUDE_DIR - Include directories for Readline
#   READLINE_LIBRARIES   - Linker flags for Readline
#   READLINE_VERSION     - Version of Readline

# This module also provides an imported target:
#   Readline::Readline   - Readline library

# On Apple systems, a pkg-config file is not provided for Readline, so we find it manually
if (APPLE)
    find_library(READLINE_LIBRARY NAMES readline)

    if (READLINE_LIBRARY)
        get_filename_component(READLINE_INCLUDE_DIR "${READLINE_LIBRARY}" DIRECTORY)

        # Extract the version number from the library filename
        file(REGEX MATCH "libreadline\\.([0-9]+)\\.dylib" READLINE_VERSION_MATCH "${READLINE_LIBRARY}")

        if (READLINE_VERSION_MATCH)
            # Extracted version number
            set(READLINE_VERSION "${CMAKE_MATCH_1}")
        endif ()

        # Set the location and include directories of the readline library
        set_target_properties(Readline::Readline PROPERTIES
                INTERFACE_INCLUDE_DIRECTORIES "${READLINE_INCLUDE_DIR}"
                IMPORTED_LOCATION "${READLINE_LIBRARY}"
        )

    else ()
        message(FATAL_ERROR "Readline library not found.")
    endif ()

else ()
    # Find the pkg-config package for Readline
    find_package(PkgConfig REQUIRED)

    pkg_check_modules(READLINE REQUIRED readline)

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

endif ()

# Print Readline information
message(STATUS "Found Readline ${READLINE_VERSION}")
message(STATUS "Readline include directories: ${READLINE_INCLUDE_DIR}")
if (APPLE)
    message(STATUS "Readline libraries: ${READLINE_LIBRARY}")
else ()
    message(STATUS "Readline libraries: ${READLINE_LIBRARIES}")
endif ()

