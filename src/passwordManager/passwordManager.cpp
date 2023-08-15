#include <iostream>
#include <filesystem>
#include "../encryption/encryptDecrypt.hpp"
#include "../utils/utils.hpp"
#include "passwords.hpp"

namespace fs = std::filesystem;

/**
 * @brief A minimalistic password manager.
 */
void passwordManager() {
    std::vector<std::pair<std::string, std::string>> passwords;
    std::string passwordFile = "/to/be/determined/later";

    std::string encryptionKey = getSensitiveInfo("Enter the master password: ");

    // Lock the memory area holding the password
    sodium_mlock(encryptionKey.data(), encryptionKey.size());

    if (!encryptionKey.empty() && fs::exists(passwordFile))
        passwords = loadPasswords(passwordFile, encryptionKey);

    while (true) {
        std::cout << "---------------------------" << std::endl;
        std::cout << "1. Add Password" << std::endl;
        std::cout << "2. Generate Password" << std::endl;
        std::cout << "3. View Passwords" << std::endl;
        std::cout << "4. Update Password" << std::endl;
        std::cout << "5. Delete Password" << std::endl;
        std::cout << "6. Save and Exit" << std::endl;
        std::cout << "---------------------------" << std::endl;

        int choice = getResponseInt("Enter your choice: ");

        if (choice == 1) {
            std::string site = getResponseStr("Enter the site/platform: ");

            std::string password = getSensitiveInfo("Enter the password: ");

            if (!isPasswordStrong(password)) {
                std::cout
                        << "Weak password! Password should have at least 8 characters and include uppercase letters,\n"
                           "lowercase letters, special characters and digits.\nPlease consider updating it."
                        << std::endl;
            }

            std::string encryptedPassword = encryptString(password, encryptionKey);
            passwords.emplace_back(site, encryptedPassword);

            std::cout << "Password added successfully." << std::endl;
        } else if (choice == 2) {
            int length = getResponseInt("Enter the length of the password to generate: ");

            int tries{0};

            while (length < 8 && tries < 3) {
                std::cout << "A strong password should be at least 8 characters long." << std::endl;
                std::cout << 2 - tries << " Trial(s) left. Try again: ";
                length = getResponseInt();
                ++tries;
            }
            if (tries == 3)
                continue;

            std::string generatedPassword = generatePassword(length);

            std::cout << "Generated password: " << generatedPassword << std::endl;
        } else if (choice == 3) {
            std::cout << "All passwords:" << std::endl;
            for (const auto &password: passwords) {
                std::cout << "Site: " << password.first << std::endl;
                std::cout << "Password: " << decryptString(password.second, encryptionKey) << std::endl;
                std::cout << "--------------------------------" << std::endl;
            }
        } else if (choice == 4) {
            std::string site = getResponseStr("Enter the site to update: ");

            std::input_iterator auto it = std::ranges::find_if(passwords.begin(), passwords.end(),
                                                               [&site](const auto &password) -> bool {
                                                                   return password.first == site;
                                                               });

            if (it != passwords.end()) {
                std::string newPassword = getSensitiveInfo("Enter the new password: ");

                if (!isPasswordStrong(newPassword)) {
                    std::cout
                            << "Weak password! Password should have at least 8 characters and include uppercase letters,\n"
                               "lowercase letters, special characters, and digits.\nPlease consider using a stronger one."
                            << std::endl;
                }

                it->second = encryptString(newPassword, encryptionKey);
                std::cout << "Password updated successfully." << std::endl;
            } else {
                std::cout << "Site not found!" << std::endl;
            }
        } else if (choice == 5) {
            std::string site = getResponseStr("Enter the site to delete: ");

            std::input_iterator auto it = std::ranges::find_if(passwords.begin(), passwords.end(),
                                                               [&site](const auto &password) -> bool {
                                                                   return password.first == site;
                                                               });

            if (it != passwords.end()) {
                passwords.erase(it);
                std::cout << "Password deleted!" << std::endl;
            } else {
                std::cout << "Site not found!" << std::endl;
            }
        } else if (choice == 6) {
            break;
        } else {
            std::cout << "Invalid choice!" << std::endl;
        }
    }
    (savePasswords(passwords, passwordFile, encryptionKey) ? std::cout << "Passwords saved!" : std::cerr
            << "Passwords not saved!") << std::endl;

    // Zero the password data and unlock the memory area
    sodium_munlock((void *) encryptionKey.data(), encryptionKey.size());

}
