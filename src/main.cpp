#include <sodium.h>
#include <gcrypt.h>
#include <unordered_map>
#include <format>
#include "encryption/encryptDecrypt.hpp"
#include "duplicateFinder/duplicateFinder.hpp"
#include "fileShredder/shredFiles.hpp"
#include "passwordManager/passwords.hpp"
#include "privacyTracks/privacyTracks.hpp"

constexpr const char *const MINIMUM_LIBGCRYPT_VERSION = "1.10.0";


int main(int argc, char **argv) {

    // No arguments required
    if (argc > 1) {
        printColor("Ignoring extra arguments: ", 'y');
        for (int i = 1; i < argc; printColor(std::format("{} ", argv[i++]), 'r')) {}
        std::cout << std::endl;
    }

    try {
        // Initialize Gcrypt
        if (!gcry_check_version(MINIMUM_LIBGCRYPT_VERSION)) {
            throw std::runtime_error(std::format("libgcrypt is too old (need {}, have {})", MINIMUM_LIBGCRYPT_VERSION,
                                                 gcry_check_version(nullptr)));
        }

        gcry_control(GCRYCTL_SUSPEND_SECMEM_WARN); // Postpone warning messages from the secure memory subsystem

        gcry_control(GCRYCTL_INIT_SECMEM, 16384, 0); // Allocate 16k secure memory

        gcry_control(GCRYCTL_RESUME_SECMEM_WARN); // Libgcrypt can now complain about secure memory

        gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0); // Initialization complete

        if (!gcry_control(GCRYCTL_INITIALIZATION_FINISHED_P))
            throw std::runtime_error("Failed to initialize libgcrypt.");

        // Initialize Sodium
        if (sodium_init() == -1)
            throw std::runtime_error("Failed to initialize libsodium.");

        // All the available tools
        std::unordered_map<int, void (*)()> apps = {
                {1, passwordManager},
                {2, encryptDecrypt},
                {3, fileShredder},
                {4, clearPrivacyTracks},
                {5, duplicateFinder}
        };

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

            } catch (const std::exception &ex) {
                std::cerr << "Error: " << ex.what() << std::endl;
                continue;

            } catch (...) {
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
