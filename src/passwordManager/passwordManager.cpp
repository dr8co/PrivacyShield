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
const string DefaultPasswordFile = "/home/draco/Desktop/dups/passes";


/**
 * @brief A simple, minimalistic password manager.
 */
void passwordManager() {
    // TODO: Exception handling
    string encryptionKey, passwordFile{DefaultPasswordFile};
    bool newSetup{false};

    // Reserve 32 bytes for the primary key.
    encryptionKey.reserve(32);
    sodium_mlock(encryptionKey.data(), 32 * sizeof(char));

    if (!fs::exists(passwordFile) || !fs::is_regular_file(passwordFile)) {
        auto [path, pass] = initialSetup();

        if (path.empty() && pass.empty()) { // user exited
            return;
        } else if (path.empty()) [[likely]] { // user provided a new primary password
            encryptionKey = pass;

            // Lock the memory of the new password
            sodium_mlock(encryptionKey.data(), encryptionKey.size() * sizeof(char));

            newSetup = true;
        } else {  // the user pointed us to an existing password records
            passwordFile = path;
        }
    }
    // Reserve about 96 KB for password records
    std::vector<passwordRecords> passwords;
    passwords.reserve(1024);
    sodium_mlock(passwords.data(), 1024 * sizeof(passwordRecords));

    if (!newSetup) {
        // preprocess the passwordFile
        string pwHash = getHash(passwordFile);

        int attempts{0};
        bool isCorrect;

        // Get the primary password
        do {
            encryptionKey = getSensitiveInfo("Enter the primary password: ");
            isCorrect = verifyPassword(encryptionKey, pwHash);
            if (!isCorrect && attempts < 2)
                std::cerr << "Wrong password, try again." << std::endl;

        } while (!isCorrect && ++attempts < 3);

        // If the password is still incorrect, exit
        if (!isCorrect) {
            throw std::runtime_error("3 incorrect password attempts.");
        }
        sodium_mlock(encryptionKey.data(), encryptionKey.size() * sizeof(char));

        // Load the saved passwords
        passwords = loadPasswords(passwordFile, encryptionKey);
    }

    // A comparator for searching and sorting the password records, based on the site and username entries
    auto comparator = [](const auto &tuple1, const auto &tuple2) noexcept -> bool {
        return std::tie(std::get<0>(tuple1), std::get<1>(tuple1)) <=>
               std::tie(std::get<0>(tuple2), std::get<1>(tuple2)) < nullptr;
    };

    // Sort the existing passwords, if any.
    std::ranges::sort(passwords, comparator);

    // Lambda to print the entries
    auto printDetails = [&encryptionKey](const auto &pw, bool decrypt = true) noexcept {
        if (const auto &site = std::get<0>(pw); !site.empty()) {
            std::cout << "Site:     ";
            printColor(site, 'c');
        }

        if (const auto &username = std::get<1>(pw); !username.empty()) {
            std::cout << "\nUsername: ";
            printColor(username, 'b');
        }

        // Highlight a weak password
        const auto &pass = decrypt ? decryptStringWithMoreRounds(std::get<2>(pw), encryptionKey) : std::get<2>(pw);
        std::cout << "\nPassword: ";
        printColor(pass, isPasswordStrong(pass) ? 'g' : 'r', true);

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

        // TODO: Find an alternative to these many if-else branches

        if (choice == 1) {
            string site = getResponseStr("Enter the site/platform: ");
            string username = getResponseStr("Username (leave blank if N/A): ");

            // Check if the record already exists in the database
            auto it = std::ranges::lower_bound(passwords, std::tie(site, username, std::ignore), comparator);

            // If the record already exists, ask the user if they want to update it
            bool update{false};
            if (it != passwords.end() && std::get<0>(*it) == site && std::get<1>(*it) == username) {
                printColor("A record with the same site and username already exists.", 'y', true);
                printColor("Do you want to update it? (y/n): ", 'b');
                update = validateYesNo();

                if (!update) continue;
            }

            string password = getSensitiveInfo("Enter the password: ");

            // The password can't be empty. Give the user 2 more tries to enter a non-empty password
            int attempts{0};
            while (password.empty() && ++attempts < 3) {
                printColor("Password can't be empty. Try again: ", 'y');
                password = getSensitiveInfo();
            }

            // If the password is still empty, continue to the next iteration
            if (password.empty()) {
                printColor("Password can't be empty. Try again later.", 'r', true);
                continue;
            }

            if (!isPasswordStrong(password)) {
                printColor(
                        "Weak password! A password should have at least 8 characters and include \nat least an"
                        "uppercase character, a lowercase, a punctuator, and a digit.", 'y', true);
                printColor("Please consider using a stronger one.", 'r', true);
            }

            string encryptedPassword = encryptStringWithMoreRounds(password, encryptionKey);
            if (update)
                std::get<2>(*it) = encryptedPassword;
            else passwords.emplace_back(site, username, encryptedPassword);

            printColor(std::format("Password {} successfully.", update ? "updated" : "added"), 'g', true);

            // Entries should always be sorted
            std::ranges::sort(passwords, comparator);

        } else if (choice == 2) {
            int length = getResponseInt("Enter the length of the password to generate: ");

            int tries{0};

            while (length < 8 && ++tries < 3) {
                printColor("A strong password should be at least 8 characters long.", 'y', true);
                printColor(std::format("{}", tries == 2 ? "Last chance:" : "Please try again:"),
                           tries == 2 ? 'r' : 'y');
                length = getResponseInt();
            }
            if (length < 8) continue;

            std::cout << "Generated password: " << generatePassword(length) << std::endl;

        } else if (choice == 3) {
            if (passwords.empty()) {
                std::cout << "No password saved yet." << std::endl;
                continue;
            } else {
                std::cout << "All passwords: (";
                printColor("red is weak", 'r');
                std::cout << ", ";
                printColor("green is strong", 'g');

                std::cout << ")\n---------------------------------------------------" << std::endl;

                for (const auto &password: passwords) {
                    printDetails(password);
                    std::cout << "---------------------------------------------------" << std::endl;
                }
            }
        } else if (choice == 4) {
            string site = getResponseStr("Enter the site to update: ");

            // Search for the site
            auto it = std::ranges::lower_bound(passwords, std::tie(site, "", std::ignore), comparator);

            if (it != passwords.end() && std::get<0>(*it) == site) { /* site found */
                std::vector<std::string> usernames;
                usernames.reserve(10);  // 10 accounts for a site is a generous estimate

                usernames.emplace_back(std::get<1>(*it));

                // Search for other usernames under the same site name
                while (std::get<0>(*++it) == site)
                    usernames.emplace_back(std::get<1>(*it));

                if (usernames.size() > 1) {
                    std::cout << "Found the following usernames for " << std::quoted(site) << ":\n";
                    for (auto &username: usernames)
                        printColor(username.empty() ? "'' [no username, reply with a blank to select]"
                                                    : username, 'c', true);

                    std::string username = getResponseStr("\nChoose one username to update:");

                    // Update the iterator
                    it = std::ranges::lower_bound(passwords, std::tie(site, username, std::ignore), comparator);
                    if (!(it != passwords.end() && std::get<0>(*it) == site && std::get<1>(*it) == username)) {
                        std::cerr << "No such username as " << std::quoted(username) << " under " << std::quoted(site)
                                  << std::endl;
                        continue;
                    }
                } else --it; // Return the iterator to the lone match

                string newUsername;
                bool updateUsername{validateYesNo("Do you want to change the username? (y/n):")};
                if (updateUsername) {
                    newUsername = getResponseStr("Enter the new username (Leave blank to delete the current one):");

                    bool abortUpdate{false};

                    // If the entered username exists, ignore the update
                    for (const auto &el: usernames) {
                        if (newUsername == el) {
                            std::cerr << "Username already exists for this site. Try again later." << std::endl;

                            // Abort the update operation in the outer loop after breaking out of this
                            abortUpdate = true;
                            break;
                        }
                    }
                    if (abortUpdate) continue;
                }

                string newPassword = getSensitiveInfo("Enter the new password (Leave blank to keep the current one): ");

                if (!newPassword.empty() && !isPasswordStrong(newPassword)) {
                    printColor(
                            "Weak password! A password should have at least 8 characters and include \nat least an"
                            " uppercase character, a lowercase, a punctuator, and a digit.", 'y', true);
                    printColor("Please consider using a stronger one.", 'r', true);
                }

                // Update the record
                if (updateUsername) std::get<1>(*it) = newUsername;
                if (!newPassword.empty()) std::get<2>(*it) = encryptStringWithMoreRounds(newPassword, encryptionKey);

                // Entries should always be sorted
                std::ranges::sort(passwords, comparator);

                if (updateUsername || !newPassword.empty())
                    printColor("Password updated successfully.", 'g', true);
                else printColor("Password not updated.", 'r', true, std::cerr);

            } else {
                printColor("Site not found!", 'r', true);
            }
        } else if (choice == 5) { // similar to update of passwords
            string site = getResponseStr("Enter the site to delete: ");

            // Search for the site
            auto it = std::ranges::lower_bound(passwords, std::tie(site, "", std::ignore), comparator);

            if (it != passwords.end() && std::get<0>(*it) == site) {
                std::vector<std::string> usernames;
                usernames.reserve(10);

                usernames.emplace_back(std::get<1>(*it));

                // Search for other usernames under the same site name
                while (std::get<0>(*++it) == site)
                    usernames.emplace_back(std::get<1>(*it));

                if (usernames.size() > 1) {
                    std::cout << "Found the following usernames for " << std::quoted(site) << ":\n";
                    for (auto &username: usernames)
                        printColor(username.empty() ? "'' [no username, reply with a blank to select]"
                                                    : username, 'c', true);

                    std::string username = getResponseStr("\nEnter the username to delete:");

                    // Update the iterator
                    it = std::ranges::lower_bound(passwords, std::tie(site, username, std::ignore), comparator);
                    if (!(it != passwords.end() && std::get<0>(*it) == site && std::get<1>(*it) == username)) {
                        std::cerr << "No such username as " << std::quoted(username) << " under " << std::quoted(site)
                                  << std::endl;
                        continue;
                    }
                } else --it; // Return the iterator to the match

                // Delete the entry
                passwords.erase(std::remove(it, passwords.end(), *it), passwords.end());

                // Make sure the entries are sorted
                if (!std::ranges::is_sorted(passwords, comparator))
                    std::ranges::sort(passwords, comparator);

                printColor("Password record deleted successfully.", 'g', true);

            } else printColor("Site not found!", 'r', true, std::cerr);

        } else if (choice == 6) {
            if (changeMasterPassword(passwords, encryptionKey))
                printColor("Master password changed successfully.", 'g', true);
            else printColor("Master password not changed.", 'r', true);
        } else if (choice == 7) {
            string query = getResponseStr("Enter the site name: ");

            auto matches = passwords | std::ranges::views::filter([&query](const auto &vec) -> bool {
                return std::get<0, string>(vec).contains(query);
            });

            if (!matches.empty()) [[likely]] {
                std::cout << "All the matches:" << std::endl;

                std::cout << "---------------------------------------------\n";
                for (const auto &el: matches) {
                    printDetails(el);
                    std::cout << "---------------------------------------------" << std::endl;
                }
            } else {
                printColor(std::format("No matches found for '{}'", query), 'r', true);

                // Fuzzy-match the query against the site names
                FuzzyMatcher matcher(passwords | std::ranges::views::elements<0>);
                auto fuzzyMatched{matcher.fuzzyMatch(query, 2)};

                if (fuzzyMatched.size() == 1) {
                    const auto &match = fuzzyMatched.at(0);

                    printColor("Did you mean '", 'c');
                    printColor(match, 'g');
                    printColor("'? (y/n):", 'c');

                    if (validateYesNo()) {
                        auto iter = std::ranges::lower_bound(passwords,
                                                             std::tie(match, std::ignore, std::ignore),
                                                             [](const auto &lhs, const auto &rhs) noexcept -> bool {
                                                                 return std::get<0>(lhs) < std::get<0>(rhs);
                                                             });

                        if (iter != passwords.end() && std::get<0>(*iter) == match) {
                            std::cout << "--------------------------------------------" << std::endl;
                            do {
                                printDetails(*iter);
                                std::cout << "--------------------------------------------" << std::endl;
                            } while (std::get<0>(*++iter) == match);
                        }

                    } else printColor("Sorry, '" + query + "' not found.", 'r', true);

                } else if (!fuzzyMatched.empty()) { /* multiple matches */
                    printColor("Did you mean one of these?:", 'b', true);
                    for (const auto &el: fuzzyMatched) {
                        printColor(el, 'g', true);
                        std::cout << "--------------------------------" << std::endl;
                    }
                }
            }
        } else if (choice == 8) {
            string fileName = getResponseStr("Enter the path to the csv file: ");
            bool hasHeader = validateYesNo("Does the file have a header? (Skip the first line?) (y/n): ");

            std::vector<passwordRecords> importedPasswords{importCsv(fileName, hasHeader)};
            auto numImported{importedPasswords.size()};

            sodium_mlock(importedPasswords.data(), numImported * sizeof(passwordRecords));

            if (importedPasswords.empty()) {
                printColor("No passwords imported.", 'y', true);
                continue;
            }

            // Sort the imported passwords
            std::ranges::sort(importedPasswords, comparator);

            // Remove duplicates from the imported passwords
            std::vector<std::tuple<string, string, string>> uniqueImportedPasswords;
            uniqueImportedPasswords.reserve(numImported); // Reserve space for efficiency

            // Add the first password entry before checking for duplicates
            uniqueImportedPasswords.emplace_back(importedPasswords[0]);

            // The following approach is significantly faster (for this specific task in this scenario)
            // than using the erase-remove idiom (erase() is expensive).
            // It is also faster than std::ranges::unique_copy, at least on my machine
            for (auto &password: importedPasswords) {
                if (std::get<0>(password) != std::get<0>(uniqueImportedPasswords.back()) ||
                    std::get<1>(password) != std::get<1>(uniqueImportedPasswords.back())) {
                    uniqueImportedPasswords.emplace_back(std::move(password));
                }
            }
            sodium_munlock(importedPasswords.data(), numImported * sizeof(passwordRecords));
            sodium_mlock(uniqueImportedPasswords.data(), uniqueImportedPasswords.size() * sizeof(passwordRecords));

            // Check if the imported passwords already exist in the database
            std::vector<passwordRecords> duplicates;
            duplicates.reserve(uniqueImportedPasswords.size());
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
            // Encrypt the passwords before importing
            std::cout << "Encrypting the imported passwords..." << std::endl;
            encryptDecryptConcurrently(uniqueImportedPasswords, encryptionKey, true, false);

            for (auto &el: uniqueImportedPasswords) {
                passwords.emplace_back(std::move(el));
            }
            sodium_munlock(uniqueImportedPasswords.data(),
                           uniqueImportedPasswords.size() * sizeof(passwordRecords));

            // Lock the passwords vector using sodium_mlock
            sodium_mlock(passwords.data(), passwords.size() * sizeof(passwordRecords));

            // Sort the password vector
            std::ranges::sort(passwords, comparator);

            if (auto uniques{uniqueImportedPasswords.size()}; uniques)
                printColor(std::format("Imported {} passwords successfully.", uniques), 'g', true);
            else printColor("Passwords not imported.", 'r', true);
        } else if (choice == 9) {
            string fileName = getResponseStr("Enter the path to save the file (leave blank for default): ");
            std::vector<passwordRecords> clearPasswords;

            clearPasswords.reserve(passwords.size());
            sodium_mlock(clearPasswords.data(), passwords.size() * sizeof(passwordRecords));

            // Copying then decrypting is more efficient than decrypting then encrypting
            clearPasswords = passwords;
            encryptDecryptConcurrently(clearPasswords, encryptionKey, false, false);

            // Export the passwords to a csv file
            fileName.empty() ? exportCsv(clearPasswords) : exportCsv(clearPasswords, fileName);

            // Zeroize the clear passwords and unlock the memory area
            sodium_munlock(clearPasswords.data(), clearPasswords.size() * sizeof(passwordRecords));

            // Warn the user about the security risk
            printColor("WARNING: The exported file contains all your passwords in plain text."
                       "\nPlease delete it securely after use.", 'r', true);
        } else if (choice == 10) {
            if (passwords.empty()) {
                printColor("No passwords to analyze.", 'r', true);
                continue;
            }
            std::vector<passwordRecords> clearPasswords{passwords};
            sodium_mlock(clearPasswords.data(), passwords.size() * sizeof(passwordRecords));

            std::cout << "Decrypting passwords..." << std::endl;
            encryptDecryptConcurrently(clearPasswords, encryptionKey, false, false);

            auto total = clearPasswords.size();

            // Analyze the passwords
            std::cout << "Analyzing passwords..." << std::endl;

            // Scan for weak passwords
            std::vector<passwordRecords> weakPasswords;
            weakPasswords.reserve(clearPasswords.size());
            sodium_mlock(weakPasswords.data(), clearPasswords.size() * sizeof(passwordRecords));

            for (const auto &password: clearPasswords) {
                if (!isPasswordStrong(std::get<2>(password)))
                    weakPasswords.emplace_back(password);
            }

            // Check for reused passwords
            std::unordered_map<string, std::unordered_set<string>> passwordMap;
            for (const auto &record: clearPasswords) {
                const string &site = std::get<0>(record);
                const string &password = std::get<2>(record);

                passwordMap[password].insert(site);
            }
            // Print the results.
            // Print the weak passwords
            auto weak{weakPasswords.size()};
            if (!weakPasswords.empty())[[likely]] {
                printColor(std::format("Found {} accounts with weak passwords:", weak), 'r', true);
                printColor("---------------------------------------------", 'r', true);
                for (const auto &password: weakPasswords) {
                    printDetails(password, false);
                    printColor("---------------------------------------------", 'r', true);
                }
                printColor(std::format("Please change the weak passwords above. "
                                       "\nYou can use the 'generate' command to generate strong passwords.\n"), 'r',
                           true);
            } else printColor("No weak passwords found. Keep it up!\n", 'g', true);

            // Zeroize the weak passwords and unlock the memory
            sodium_munlock(weakPasswords.data(), weakPasswords.size() * sizeof(passwordRecords));

            // Print sites with reused passwords
            std::size_t reused{0};
            for (const auto &entry: passwordMap) {
                const std::unordered_set<string> &sites = entry.second;
                if (const auto &x = sites.size(); x > 1) {
                    printColor(std::format("Password '{}' is reused on {} sites:", entry.first, x), 'y', true);
                    for (const string &site: sites) {
                        printColor(site + "\n", 'm');
                    }
                    std::cout << std::endl;
                    ++reused;
                }
            }
            if (reused) {
                printColor(std::format("{} password{} been reused.", reused,
                                       reused == 1 ? " has" : "s have"), 'r', true);
            } else printColor("Nice!! No password reuse detected.", 'g', true);

            printColor(std::format("{} use unique passwords to minimize the impact of their compromise.",
                                   reused ? "Please" : "Always"), reused ? 'r' : 'c', true);

            sodium_munlock(clearPasswords.data(), clearPasswords.size() * sizeof(passwordRecords));

            // Print the statistics
            std::cout << "\nTotal passwords: " << total << std::endl;
            if (weak > 0)[[likely]] {
                char col{std::cmp_greater(weak, total / 4) ? 'r' : 'y'};

                printColor(std::format("{}% of your passwords are weak.",
                                       std::round(static_cast<double>(weak) / static_cast<double>(total) * 100 * 100) /
                                       100), col, true);
            } else printColor("All your passwords are strong. Keep it up!", 'g', true);

        } else if (choice == 11) {
            break;
        } else {
            printColor("Invalid choice!", 'r', true);
        }
    }
    if (savePasswords(passwords, passwordFile, encryptionKey))
        printColor("Passwords saved successfully", 'g', true);
    else printColor("Passwords not saved!", 'r', true, std::cerr);

    // Zeroize the password and unlock the memory
    sodium_munlock(encryptionKey.data(), encryptionKey.size() * sizeof(char));

}
