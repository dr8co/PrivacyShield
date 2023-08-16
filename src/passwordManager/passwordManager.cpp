#include <iostream>
#include <filesystem>
#include "../encryption/encryptDecrypt.hpp"
#include "../utils/utils.hpp"
#include "passwords.hpp"

namespace fs = std::filesystem;
const std::string passwordFile = "/to/be/determined/later";


/**
 * @brief A minimalistic password manager.
 */
void passwordManager() {
    std::vector<passwordRecords> passwords;

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
            std::string username = getResponseStr("Username (leave blank if N/A): ");

            // Check if the record already exists in the database
            auto it = std::ranges::find_if(passwords, [&site, &username](const auto &pw) noexcept -> bool {
                return std::get<0>(pw) == site && std::get<1>(pw) == username;
            });

            // If the record already exists, ask the user if they want to update it
            if (it != passwords.end()) {
                printColor("A record with the same site and username already exists.", 'y', true);
                printColor("Do you want to update it? (y/n): ", 'b');
                char response;
                std::cin >> response;
                if (response == 'n' || response == 'N')
                    continue;
                else if (response == 'y' || response == 'Y') {
                    passwords.erase(it);
                } else {
                    printColor("Invalid response. Try again.", 'r', true);
                    continue;
                }
            }

            std::string password = getSensitiveInfo("Enter the password: ");

            // The password can't be empty. Give the user 2 more tries to enter a non-empty password
            int attempts{0};
            while (password.empty() && attempts < 2) {
                printColor("Password can't be empty. Try again: ", 'y');
                password = getSensitiveInfo();
                ++attempts;
            }

            // If the password is still empty, continue to the next iteration
            if (password.empty()) {
                printColor("Password can't be empty. Try again later.", 'r', true);
                continue;
            }

            if (!isPasswordStrong(password))
                printColor("Weak password! Password should have at least 8 characters and include uppercase letters,\n"
                           "lowercase letters, special characters and digits.\nPlease consider updating it.", 'y',
                           true);


            std::string encryptedPassword = encryptString(password, encryptionKey);
            passwords.emplace_back(site, username, encryptedPassword);

            printColor("Password added successfully.", 'g', true);
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
