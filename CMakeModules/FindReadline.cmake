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
####################################################################################
#
# A CMake module to find a local installation of the Readline library

# Find Readline library
# This module sets the following variables:
#   READLINE_FOUND       - True if Readline is found
#   READLINE_INCLUDE_DIR - Include directories for Readline
#   READLINE_LIBRARIES   - Linker flags for Readline (not on Apple)
#   READLINE_VERSION     - Version of Readline

# This module also provides an imported target:
#   Readline::Readline   - Readline library

# Find the pkg-config package for Readline
find_package(PkgConfig REQUIRED)

pkg_check_modules(READLINE readline)

if (READLINE_FOUND AND NOT APPLE)
    # Set the Readline variables
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
            NAMES libreadline.so libreadline.a
            HINTS ${READLINE_LIBRARY_DIRS}
            PATHS
            /usr/lib
            /usr/lib/*
            /opt/local/lib
            /opt/homebrew/lib
            /opt/homebrew/opt/readline/lib
            /opt/homebrew/Cellar/readline/*/lib
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

# Find the Readline library manually on Apple
# This is necessary because the pkg-config file might not be provided on Apple
if (NOT READLINE_FOUND AND APPLE)
    # Find library manually
    find_library(READLINE_LIBRARY REQUIRED
            NAMES libreadline.dylib libreadline.a
            PATHS
            /usr/local/opt/readline/lib
            /usr/local/lib
            /opt/local/lib
            /usr/lib
            /opt/homebrew/lib
            /opt/homebrew/opt/readline/lib
            /opt/homebrew/Cellar/readline/*/lib
            NO_DEFAULT_PATH
    )

    # Get the directory of the Readline library
    get_filename_component(READLINE_INCLUDE_DIR "${READLINE_LIBRARY}" DIRECTORY)

    # Create an imported target for the readline library
    add_library(Readline::Readline INTERFACE IMPORTED)

    # Configure the imported target
    set_target_properties(Readline::Readline PROPERTIES
            INTERFACE_LINK_LIBRARIES "${READLINE_LIBRARY}"
            INTERFACE_INCLUDE_DIRECTORIES "${READLINE_INCLUDE_DIR}"
            IMPORTED_LOCATION "${READLINE_LIBRARY}"
    )

    set(READLINE_FOUND TRUE)
    set(READLINE_VERSION "unknown")
endif ()

if (READLINE_LIBRARY)
    set(READLINE_FOUND TRUE)
else ()
    set(READLINE_FOUND FALSE)
    message(FATAL_ERROR "Readline library not found.")
endif ()

# Print information about the Readline library
function(print_readline_info)
    message(STATUS "Found Readline ${READLINE_VERSION}")
    message(STATUS "Readline include directories: ${READLINE_INCLUDE_DIR}")
    if (NOT APPLE)
        message(STATUS "Readline libraries: ${READLINE_LIBRARIES}")
    else ()
        message(STATUS "Readline library: ${READLINE_LIBRARY}")
    endif ()
endfunction()

print_readline_info()

