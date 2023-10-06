// Privacy Shield: A Suite of Tools Designed to Facilitate Privacy Management.
// Copyright (C) 2023  Ian Duncan <dr8co@duck.com>
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

#include "duplicateFinder/duplicateFinder.hpp"
#include "encryption/encryptDecrypt.hpp"
#include "fileShredder/shredFiles.hpp"
#include "passwordManager/passwords.hpp"
#include "privacyTracks/privacyTracks.hpp"
#include <csignal>
#include <sodium.h>
#include <gcrypt.h>
#include <unordered_map>
#include <format>
#include <functional>
#include <unistd.h>
#include <sys/resource.h>

constexpr const char *const MINIMUM_LIBGCRYPT_VERSION = "1.10.0";


int main(int argc, char **argv) {
    // The program should be launched in interactive mode
    if (!isatty(STDIN_FILENO)) {
        if (errno == ENOTTY) {
            printColor(std::format("{} is meant to be run interactively.", argv[0]), 'r', true, std::cerr);
            return 1;
        }
    }
    // Disable core dumping for security reasons
    rlimit coreLimit{0, 0};
    if (setrlimit(RLIMIT_CORE, &coreLimit) != 0) {
        printColor("Failed to disable core dumps.", 'r', true, std::cerr);
        return 1;
    }

    // No arguments required
    if (argc > 1) {
        printColor("Ignoring extra arguments: ", 'y');
        for (int i = 1; i < argc; printColor(std::format("{} ", argv[i++]), 'r')) {}
        std::cout << std::endl;
    }

    // Handle keyboard interrupt (Ctrl+C) signals from the user
    struct sigaction act{};
    act.sa_handler = [](int num [[maybe_unused]]) -> void {
        printColor("Keyboard interrupt detected. Unsaved data might be lost if you quit now."
                   "\nDo you still want to quit? (y/n):", 'r');
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

        // All the available tools
        std::unordered_map<int, std::function<void(void)>> apps = {
                {1, passwordManager},
                {2, encryptDecrypt},
                {3, fileShredder},
                {4, clearPrivacyTracks},
                {5, duplicateFinder}
        };

        // Display information about the program
        std::cout << "\nPrivacy Shield 1.0.0\n"
                     "Copyright (C) 2023 Ian Duncan.\n"
                     "This program comes with ABSOLUTELY NO WARRANTY.\n"
                     "This is a free software; you are free to change and redistribute it\n"
                     "under the terms of the GNU General Public License v3 or later.\n"
                     "For more information, see https://www.gnu.org/licenses/gpl.html.\n"
                  << std::endl;

        while (true) {
            std::cout << "-------------------------------------\n";
            std::cout << "1. Manage passwords\n";
            std::cout << "2. Encrypt/decrypt files\n";
            std::cout << "3. Shred files\n";
            std::cout << "4. Clear browser privacy traces\n";
            std::cout << "5. Find duplicate files\n";
            std::cout << "6. Exit\n";
            std::cout << "-------------------------------------" << std::endl;

            int choice = getResponseInt("What would you like to do? (Enter 1 or 2, 3..)");

            try {
                auto iter = apps.find(choice);

                if (iter != apps.end())
                    iter->second();
                else if (choice == 6)
                    break;
                else printColor("Invalid choice!", 'r', true, std::cerr);

            } catch (const std::bad_function_call &bc) { // In case the std::function objects are called inappropriately
                std::cerr << "Bad function call: " << bc.what() << std::endl;
                continue;

            } catch (const std::exception &ex) {
                std::cerr << "Error: " << ex.what() << std::endl;
                continue;

            } catch (...) { // All other exceptions, if any
                std::cerr << "An error occurred." << std::endl;
                continue;
            }
        }

        return 0;

    } catch (const std::exception &ex) {
        std::cerr << "Error: " << ex.what() << std::endl;
        return 1;

    } catch (...) {
        std::cerr << "Something went wrong." << std::endl;
        return 1;
    }

}
