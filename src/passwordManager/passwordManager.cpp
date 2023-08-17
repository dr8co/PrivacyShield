#include <iostream>
#include <filesystem>
#include <algorithm>
#include <format>
#include <ranges>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <cmath>
#include "../encryption/encryptDecrypt.hpp"
#include "../utils/utils.hpp"
#include "passwords.hpp"
#include "FuzzyMatcher.hpp"

namespace fs = std::filesystem;
using string = std::string;
const string DefaultPasswordFile = "/to/be/determined/later";


/**
 * @brief A simple, minimalistic password manager.
 */
void passwordManager() {
    string encryptionKey, passwordFile{DefaultPasswordFile};
    bool newSetup{false};

    if (!fs::exists(passwordFile) || !fs::is_regular_file(passwordFile)) {
        auto [path, pass] = initialSetup();
        sodium_mlock(pass.data(), pass.size());

        if (path.empty()) [[likely]] { // user provided a new primary password
            encryptionKey = pass;

            // Lock the memory area holding the new password
            sodium_mlock(encryptionKey.data(), encryptionKey.size());

            newSetup = true;
        } else if (path.empty() && pass.empty()) { // user exited
            return;
        } else {
            passwordFile = path;
        }

        sodium_munlock(pass.data(), pass.size());
    }

    std::vector<passwordRecords> passwords;

    if (!newSetup) {
        // preprocess the passwordFile
        string pwHash = getHash(passwordFile);

        int attempts{0};
        bool isCorrect;

        // Get the primary password
        do {
            encryptionKey = getSensitiveInfo("Enter the master password: ");
            isCorrect = verifyPassword(encryptionKey, pwHash);
            if (!isCorrect && attempts < 2)
                std::cerr << "Sorry, try again." << std::endl;

            ++attempts;
        } while (!isCorrect && attempts < 3);

        // If the user failed to enter the correct password 3 times, exit
        if (attempts == 3) {
//            throw std::invalid_argument("3 incorrect password attempts.");
        }

        // Lock the memory area holding the password
        sodium_mlock(encryptionKey.data(), encryptionKey.size());

        // Load the saved passwords
        passwords = loadPasswords(passwordFile, encryptionKey);
    }

    // A lambda to help sort entries
    auto comparator = [](const auto &tuple1, const auto &tuple2) noexcept -> bool {
        return std::ranges::lexicographical_compare(std::get<0>(tuple1), std::get<0>(tuple2));
    };

    // Initially sort the passwords
    std::ranges::sort(passwords, comparator);

    // Lambda to print the entries
    auto printDetails = [&encryptionKey](const auto &pw, bool decrypt = true) noexcept {
        if (string site = std::get<0>(pw); !site.empty())
            std::cout << "Site: " << site;

        if (string username = std::get<1>(pw); !username.empty())
            std::cout << "\nUsername: " << username;

        std::cout << "\nPassword: " << (decrypt ? decryptString(std::get<2>(pw), encryptionKey) : std::get<2>(pw))
                  << std::endl;

    };

    while (true) {
        std::cout << "-----------------------------------" << std::endl;
        std::cout << "1. Add new Password" << std::endl;
        std::cout << "2. Generate Password" << std::endl;
        std::cout << "3. View All Passwords" << std::endl;
        std::cout << "4. Update Password" << std::endl;
        std::cout << "5. Delete Password" << std::endl;
        std::cout << "6. Change the master Password" << std::endl;
        std::cout << "7. Search passwords" << std::endl;
        std::cout << "8. Import passwords" << std::endl;
        std::cout << "9. Export passwords" << std::endl;
        std::cout << "10. Analyze passwords" << std::endl;
        std::cout << "11. Save and Exit" << std::endl;
        std::cout << "-----------------------------------" << std::endl;

        int choice = getResponseInt("Enter your choice: ");

        if (choice == 1) {
            string site = getResponseStr("Enter the site/platform: ");
            string username = getResponseStr("Username (leave blank if N/A): ");

            // Check if the record already exists in the database
            auto it = std::ranges::find_if(passwords, [&site, &username](const auto &pw) noexcept -> bool {
                return std::get<0>(pw) == site && std::get<1>(pw) == username;
            });

            // If the record already exists, ask the user if they want to update it
            if (it != passwords.end()) {
                printColor("A record with the same site and username already exists.", 'y', true);
                printColor("Do you want to update it? (y/n): ", 'b');
                if (validateYesNo())
                    passwords.erase(it);
            }

            string password = getSensitiveInfo("Enter the password: ");

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


            string encryptedPassword = encryptString(password, encryptionKey);
            passwords.emplace_back(site, username, encryptedPassword);

            printColor("Password added successfully.", 'g', true);

            // Entries should always be sorted
            std::ranges::sort(passwords, comparator);

        } else if (choice == 2) {
            int length = getResponseInt("Enter the length of the password to generate: ");

            int tries{0};

            while (length < 8 && tries < 3) {
                printColor("A strong password should be at least 8 characters long.", 'y', true);
                printColor(std::format("{} Trial(s) left. Try again: ", 2 - tries), 'y');
                length = getResponseInt();
                ++tries;
            }
            if (tries == 3)
                continue;

            string generatedPassword = generatePassword(length);

            std::cout << "Generated password: " << generatedPassword << std::endl;

        } else if (choice == 3) {
            std::cout << "All passwords:" << std::endl;
            std::cout << "---------------------------------------------------" << std::endl;

            for (const auto &password: passwords) {
                printDetails(password);
                std::cout << "---------------------------------------------------" << std::endl;
            }
        } else if (choice == 4) {
            string site = getResponseStr("Enter the site to update: ");

            auto it = std::ranges::find_if(passwords, [&site](const auto &password) -> bool {
                return std::get<0>(password) == site;
            });

            if (it != passwords.end()) {
                string newPassword = getSensitiveInfo("Enter the new password: ");

                if (!isPasswordStrong(newPassword))
                    printColor(
                            "Weak password! Password should have at least 8 characters and include uppercase letters,\n"
                            "lowercase letters, special characters, and digits.\nPlease consider using a stronger one.",
                            'y', true);

                std::get<2>(*it) = encryptString(newPassword, encryptionKey);
                printColor("Password updated successfully.", 'g', true);
            } else {
                printColor("Site not found!", 'r', true);
            }
        } else if (choice == 5) {
            // TODO: Update this segment,
            //  several records can exist under the same site name but with different usernames.
            string site = getResponseStr("Enter the site to delete: ");

            auto it = std::ranges::find_if(passwords, [&site](const auto &password) -> bool {
                return std::get<0>(password) == site;
            });

            if (it != passwords.end()) {
                passwords.erase(it);
                printColor("Password deleted successfully.", 'g', true);
            } else {
                printColor("Site not found!", 'r', true);
            }
        } else if (choice == 6) {
            if (changeMasterPassword(encryptionKey))
                printColor("Master password changed successfully.", 'g', true);
            else printColor("Master password not changed.", 'r', true);
        } else if (choice == 7) {
            string query = getResponseStr("Enter the site name: ");

            // TODO: consider case-insensitive querying.

            auto matches = passwords | std::ranges::views::filter([&query](const auto &vec) -> bool {
                return std::get<0, string>(vec).contains(query);
            });

            if (!matches.empty()) [[likely]] {
                std::cout << "All the matches:" << std::endl;

                for (const auto &el: matches) {
                    printDetails(el);
                }
            } else {
                printColor(std::format("No matches found for '{}'.", query), 'r', true);
                std::vector<string> sites(passwords.size());
                for (string const &el: passwords | std::ranges::views::elements<0>) {
                    sites.emplace_back(el);
                }
                FuzzyMatcher matcher(sites);
                auto fuzzyMatched = matcher.fuzzyMatch(query, 2);
                if (fuzzyMatched.size() == 1) {
                    printColor(std::format("Did you mean '{}'? (y/n) ", fuzzyMatched[0]), 'b', false);
                    if (validateYesNo()) {
                        auto it = std::ranges::find_if(passwords, [&fuzzyMatched](const auto &vec) -> bool {
                            return std::get<0>(vec) == fuzzyMatched[0];
                        });
                        if (it != passwords.end())
                            printDetails(*it);

                    } else printColor("Sorry", 'r', true);
                } else if (!fuzzyMatched.empty()) {
                    printColor("Did you mean one of these?", 'b', true);
                    for (const auto &el: fuzzyMatched) {
                        std::cout << el << std::endl;
                    }
                }
            }
        } else if (choice == 8) {
            string fileName = getResponseStr("Enter the path to the csv file: ");
            bool hasHeader = validateYesNo("Does the file have a header? (Skip the first line?) (y/n): ");

            std::vector<passwordRecords> importedPasswords = importCsv(fileName, hasHeader);
            sodium_mlock(importedPasswords.data(), importedPasswords.size() * sizeof(passwordRecords));

            if (importedPasswords.empty()) {
                printColor("No passwords imported.", 'y', true);
                continue;
            }

            // Sort the imported passwords
            std::ranges::sort(importedPasswords, comparator);

            // Remove duplicates from the imported passwords
            std::vector<std::tuple<string, string, string>> uniqueImportedPasswords;
            uniqueImportedPasswords.reserve(importedPasswords.size()); // Reserve space for efficiency

            // Add the first password entry before checking for duplicates
            uniqueImportedPasswords.emplace_back(importedPasswords[0]);

            // This approach is faster than using std::ranges::unique, apparently. (the expensive erase() call is avoided)
            for (size_t i = 1; i < importedPasswords.size(); ++i) {
                if (std::get<0>(importedPasswords[i]) != std::get<0>(uniqueImportedPasswords.back()) ||
                    std::get<1>(importedPasswords[i]) != std::get<1>(uniqueImportedPasswords.back())) {
                    uniqueImportedPasswords.emplace_back(importedPasswords[i]);
                }
            }
            sodium_mlock(uniqueImportedPasswords.data(), uniqueImportedPasswords.size() * sizeof(passwordRecords));

            // Check if the imported passwords already exist in the database
            std::vector<passwordRecords> duplicates;
            for (const auto &importedPassword: uniqueImportedPasswords) {
                if (std::ranges::binary_search(passwords, importedPassword, comparator)) {
                    duplicates.emplace_back(importedPassword);
                }
            }

            // If there are duplicates, ask the user if they want to overwrite them
            if (!duplicates.empty()) {
                printColor("Warning: The following passwords already exist in the database:", 'y', true);
                for (const auto &password: duplicates) {
                    printDetails(password, false);
                }
                printColor("Do you want to overwrite/update them? (y/n): ", 'b', true);
                if (validateYesNo()) {
                    // Remove the duplicates from the existing passwords so that they can be replaced
                    passwords.erase(std::remove_if(passwords.begin(), passwords.end(),
                                                   [&duplicates, &comparator](const auto &password) -> bool {
                                                       return std::ranges::binary_search(duplicates,
                                                                                         password, comparator);
                                                   }), passwords.end());
                } else {
                    printColor("Warning: Duplicate passwords not imported.", 'y', true);
                    // Remove the duplicates (already in our database) from the imported passwords
                    uniqueImportedPasswords.erase(
                            std::remove_if(uniqueImportedPasswords.begin(), uniqueImportedPasswords.end(),
                                           [&duplicates, &comparator](const auto &password) {
                                               return std::ranges::binary_search(duplicates, password,
                                                                                 comparator);
                                           }), uniqueImportedPasswords.end());
                }
            }

            // A lambda to encrypt the passwords
            auto encryptPasswords = [&encryptionKey](const auto &password) -> passwordRecords {
                return {std::get<0>(password), std::get<1>(password),
                        encryptString(std::get<2>(password), encryptionKey)};
            };

            // Encrypt the passwords before importing
            std::ranges::transform(uniqueImportedPasswords, std::back_inserter(passwords), encryptPasswords);

            // Zeroize the imported passwords and unlock the memory area
            sodium_munlock(uniqueImportedPasswords.data(),
                           uniqueImportedPasswords.size() * sizeof(passwordRecords));

            // Lock the passwords vector using sodium_mlock
            sodium_mlock(passwords.data(), passwords.size() * sizeof(passwordRecords));

            // Sort the password vector
            std::ranges::sort(passwords, comparator);

            printColor(std::format("Imported {} passwords successfully.", uniqueImportedPasswords.size()), 'g', true);
        } else if (choice == 9) {
            string fileName = getResponseStr("Enter the path to save the file (leave blank for default): ");
            std::vector<passwordRecords> clearPasswords;

            // A lambda to decrypt the passwords
            auto decryptPasswords = [&encryptionKey](const auto &password) -> passwordRecords {
                return {std::get<0>(password), std::get<1>(password),
                        decryptString(std::get<2>(password), encryptionKey)};
            };

            // Decrypt the passwords before exporting
            std::ranges::transform(passwords, std::back_inserter(clearPasswords), decryptPasswords);

            // Lock the clear passwords vector using sodium_mlock
            sodium_mlock(clearPasswords.data(), clearPasswords.size() * sizeof(passwordRecords));

            // Export the passwords to a csv file
            fileName.empty() ? exportCsv(clearPasswords) : exportCsv(clearPasswords, fileName);

            // Zeroize the clear passwords and unlock the memory area
            sodium_munlock(clearPasswords.data(), clearPasswords.size() * sizeof(passwordRecords));

            // Warn the user about the security risk
            printColor("WARNING: The exported file contains all your passwords in plain text. "
                       "Please delete it securely after use.", 'y', true);
        } else if (choice == 10) {
            if (passwords.empty()) {
                printColor("No passwords to analyze.", 'r', true);
                continue;
            }
            std::vector<passwordRecords> clearPasswords;

            // A lambda to decrypt the passwords
            auto decryptPasswords = [&encryptionKey](const auto &password) -> passwordRecords {
                return {std::get<0>(password), std::get<1>(password),
                        decryptString(std::get<2>(password), encryptionKey)};
            };

            // Decrypt the passwords before analyzing
            std::ranges::transform(passwords, std::back_inserter(clearPasswords), decryptPasswords);

            // Lock the clear passwords vector using sodium_mlock
            sodium_mlock(clearPasswords.data(), clearPasswords.size() * sizeof(passwordRecords));
            auto total = clearPasswords.size();

            // Analyze the passwords using isPasswordStrong
            std::cout << "Analyzing passwords..." << std::endl;
            std::vector<passwordRecords> weakPasswords;
            for (const auto &password: clearPasswords) {
                if (!isPasswordStrong(std::get<2>(password))) {
                    weakPasswords.emplace_back(password);
                }
            }
            // Lock the weak passwords vector using sodium_mlock
            sodium_mlock(weakPasswords.data(), weakPasswords.size() * sizeof(passwordRecords));
            auto weak = weakPasswords.size();

            // Check for reused passwords
            std::unordered_map<string, std::unordered_set<string>> passwordMap;
            // TODO: Reorder logic here
            for (const auto &record: clearPasswords) {
                string site = std::get<0>(record);
                string password = std::get<2>(record);

                passwordMap[password].insert(site);
            }

            // Print sites with reused passwords
            for (const auto &entry: passwordMap) {
                const std::unordered_set<string> &sites = entry.second;
                if (const auto &x = sites.size(); x > 1) {
                    printColor(std::format("Password '{}' is reused on {} sites:", entry.first, x), 'y', true);
                    for (const string &site: sites) {
                        printColor(site + "\n", 'y');
                    }
                    std::cout << std::endl;
                }
            }

            // Zeroize the clear passwords and unlock the memory area
            sodium_munlock(clearPasswords.data(), clearPasswords.size() * sizeof(passwordRecords));

            // Print the weak passwords
            if (!weakPasswords.empty())[[likely]] {
                printColor(std::format("Found {} weak passwords.", weak), 'r', true);
                printColor("----------------------------------------", 'r', true);
                for (const auto &password: weakPasswords) {
                    printDetails(password, false);
                    printColor("----------------------------------------", 'r', true);
                }
                printColor(std::format("Please change the weak passwords above. "
                                       "\nYou can use the 'generate' command to generate strong passwords."), 'r',
                           true);
            } else printColor("No weak passwords found!", 'g', true);

            // Print the statistics
            std::cout << "\nTotal passwords: " << total << std::endl;
            if (weak > 0)[[likely]] {
                char col{std::cmp_greater(weak, total / 2) ? 'r' : 'y'};

                printColor(std::format("{}% of your passwords are weak.",
                                       std::round(static_cast<double>(weak) / static_cast<double>(total) * 100 * 100) /
                                       100), col, true);
            } else printColor("All your passwords are strong. Keep it up!", 'g', true);

            // Zeroize the weak passwords and unlock the memory area
            sodium_munlock(weakPasswords.data(), weakPasswords.size() * sizeof(passwordRecords));
        } else if (choice == 11) {
            break; //end of 7
        } else {
            printColor("Invalid choice!", 'r', true);
            // end of default
        }
    }
    if (savePasswords(passwords, passwordFile, encryptionKey))
        printColor("Passwords saved!", 'g', true);
    else printColor("Passwords not saved!", 'r', true);


    // Zeroize the password and unlock the memory area
    sodium_munlock(encryptionKey.data(), encryptionKey.size());

}
