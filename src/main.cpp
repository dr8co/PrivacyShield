// Privacy Shield: A Suite of Tools Designed to Facilitate Privacy Management.
// Copyright (C) 2024  Ian Duncan <dr8co@duck.com>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see https://www.gnu.org/licenses.

#include <csignal>
#include <sodium.h>
#include <gcrypt.h>
#include <format>
#include <functional>
#include <unistd.h>
#include <sys/resource.h>
#include <iostream>

import duplicateFinder;
import privacyTracks;
import encryption;
import passwordManager;
import fileShredder;
import mimallocSTL;
import utils;

constexpr auto MINIMUM_LIBGCRYPT_VERSION = "1.10.0";


int main(const int argc, const char **argv) {
    // The program should be launched in interactive mode
    if (!isatty(STDIN_FILENO)) {
        if (errno == ENOTTY) {
            printColoredErrorln('r', "{} is meant to be run interactively.", argv[0]);
            return 1;
        }
    }
    // Disable core dumping for security reasons
    if (constexpr rlimit coreLimit{0, 0}; setrlimit(RLIMIT_CORE, &coreLimit) != 0) {
        printColoredErrorln('r', "Failed to disable core dumps.");
        return 1;
    }

    // Configure the color output, if necessary
    configureColor();

    // Only the first argument is considered
    if (argc > 1) {
        // Disable color output if requested
        if (std::string_view(argv[1]) == "--no-color" || std::string_view(argv[1]) == "-nc") {
            configureColor(true);
        } else {
            printColoredError('y', "The option ");
            printColoredError('r', "{} ", argv[1]);
            printColoredErrorln('y', "is not recognized.");

            printColoredError('y', "Usage: ");
            printColoredErrorln('r', "{} [--no-color | -nc]", argv[0]);
        }
    }

    if (argc > 2) {
        printColoredOutput('y', "Ignoring extra arguments: ", 'y');
        for (int i = 2; i < argc; printColoredOutput('r', "{} ", argv[i++])) {
        }
        std::cout << std::endl;
    }

    // Handle the keyboard interrupt (SIGINT) signal (i.e., Ctrl+C)
    struct sigaction act{};
    act.sa_handler = [](int /* unused */) noexcept -> void {
        printColoredOutput('r', "Keyboard interrupt detected.\nUnsaved data might be lost if you quit now."
                           "\nDo you still want to quit? (y/n):");
        if (validateYesNo()) std::exit(1);
    };

    // Block all other signals while the signal handler is running
    sigfillset(&act.sa_mask);
    act.sa_flags = SA_RESTART; // Restart system calls if interrupted by the handler

    // Set the handler for SIGINT
    if (sigaction(SIGINT, &act, nullptr) == -1) {
        perror("sigaction");
        return 1;
    }

    try {
        // Initialize Gcrypt
        if (!gcry_check_version(MINIMUM_LIBGCRYPT_VERSION)) {
            throw std::runtime_error(std::format("libgcrypt is too old (need {}, have {}).",
                                                 MINIMUM_LIBGCRYPT_VERSION, gcry_check_version(nullptr)));
        }

        gcry_control(GCRYCTL_SUSPEND_SECMEM_WARN); // Postpone warning messages from the secure memory subsystem

        gcry_control(GCRYCTL_INIT_SECMEM, 16384, 0); // Allocate 16k secure memory

        gcry_control(GCRYCTL_RESUME_SECMEM_WARN); // Libgcrypt can now complain about secure memory

        gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0); // Initialization complete

        // Check if initialization was successful
        if (!gcry_control(GCRYCTL_INITIALIZATION_FINISHED_P))
            throw std::runtime_error("Failed to initialize libgcrypt.");

        // Initialize Sodium
        if (sodium_init() == -1)
            throw std::runtime_error("Failed to initialize libsodium.");

        // Display information about the program
        printColoredOutputln('c', "\nPrivacy Shield 2.5.0");
        printColoredOutputln('b', "Copyright (C) 2024 Ian Duncan.");

        printColoredOutput('g', "This program comes with ");
        printColoredOutputln('r', "ABSOLUTELY NO WARRANTY.");

        printColoredOutput('g', "This is a free software; you are free to change and redistribute it\n"
                           "under the terms of the ");
        printColoredOutput('r', "GNU General Public License v3 ");
        printColoredOutputln('g', "or later.");

        printColoredOutput('g', "For more information, see ");
        printColoredOutputln('b', "https://www.gnu.org/licenses/gpl.html.");

        // All the available tools
        miSTL::unordered_map<int, std::function<void()> > apps = {
            {1, passwordManager},
            {2, encryptDecrypt},
            {3, fileShredder},
            {4, clearPrivacyTracks},
            {5, duplicateFinder}
        };

        // Applications loop
        while (true) {
            printColoredOutputln('c', "-------------------------------------");
            printColoredOutputln('b', "1. Manage passwords");
            printColoredOutputln('g', "2. Encrypt/decrypt files");
            printColoredOutputln('m', "3. Shred files");
            printColoredOutputln('y', "4. Clear browser privacy traces");
            printColoredOutputln('b', "5. Find duplicate files");
            printColoredOutputln('r', "6. Exit");
            printColoredOutputln('c', "-------------------------------------");

            const int choice = getResponseInt("What would you like to do? (Enter 1 or 2, 3..)");

            try {
                if (const auto iter = apps.find(choice); iter != apps.end())
                    iter->second();
                else if (choice == 6)
                    break;
                else printColoredErrorln('r', "Invalid choice!");
            } catch (const std::bad_function_call &bc) {
                // In case the std::function objects are called inappropriately
                printColoredErrorln('r', "Bad function call: {}", bc.what());
            } catch (const std::exception &ex) {
                printColoredErrorln('r', "Error: {}", ex.what());
            } catch (...) {
                // All other exceptions, if any
                printColoredErrorln('r', "An error occurred.");
            }
        }

        return 0;
    } catch (const std::exception &ex) {
        printColoredErrorln('r', "Error: {}", ex.what());
        return 1;
    } catch (...) {
        printColoredErrorln('r', "Something went wrong.");
        return 1;
    }
}
