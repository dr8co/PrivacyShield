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

module;

#include <filesystem>
#include <algorithm>
#include <format>
#include <ranges>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <cmath>
#include <random>
#include <map>
#include <iostream>

import utils;
import FuzzyMatcher;
import secureAllocator;

module passwordManager;

namespace fs = std::filesystem;
using string = std::string;
const string DefaultPasswordFile = getHomeDir() + "/.privacyShield/passwords";

/// \brief A binary predicate for searching, sorting, and deduplication of the password records,
/// based on the site and username members of a password tuple.
/// \param lhs a password record tuple.
/// \param rhs another record to be compared with lhs.
/// \return true if lhs is less than (i.e. is ordered before) rhs, else false.
bool constexpr comparator
// Avoid a compiler error on ignored scoped attribute directives (-Werror=attributes is enabled in debug config),
// while still encouraging both Clang and GCC compilers to inline the function.
#if __clang__
[[clang::always_inline]]
#elif __GNUC__
[[gnu::always_inline]]
#endif
        (const auto &lhs, const auto &rhs) noexcept {
    // Compare the site and username members of the tuples
    return std::tie(std::get<0>(lhs), std::get<1>(lhs)) <
           std::tie(std::get<0>(rhs), std::get<1>(rhs));
}

/// \brief Prints the details of a password record.
/// \param pw a password tuple.
/// \param isStrong a boolean value indicating if the password is strong or not.
constexpr void printPasswordDetails(const auto &pw, const bool &isStrong = false) noexcept {
    const auto &[site, username, pass]{pw};
    if (!site.empty()) {
        // Skip blank entries
        std::cout << "Site/app: ";
        printColor(site, 'c');
    }

    if (!username.empty()) {
        std::cout << "\nUsername: ";
        printColor(username, 'b');
    }
    // Highlight a weak password
    std::cout << "\nPassword: ";
    printColor(pass, isStrong ? 'g' : 'r', true);
}

/// \brief This function computes the strength of each password in the provided list of passwords.
///
/// The function iterates over the list of passwords and for each password, it checks if the password is strong or not.
/// The result of this check (a boolean value) is stored in the corresponding index in the pwStrengths vector.
/// A password is considered strong if it meets certain criteria defined in the isPasswordStrong function.
///
/// \param passwords A vector of tuples, where each tuple represents a password record.
/// \param pwStrengths A vector of boolean values where each element represents the strength of the corresponding password
/// in the passwords vector. It is resized to match the size of the passwords vector.
///
/// \note This function is always inlined by the compiler.
constexpr void computeStrengths
#if __clang__
[[clang::always_inline]]
#elif __GNUC__
[[gnu::always_inline]]
#endif
        (const privacy::vector <passwordRecords> &passwords, std::vector<bool> &pwStrengths) {
    pwStrengths.resize(passwords.size());
    for (std::size_t i = 0; i < passwords.size(); ++i) {
        pwStrengths[i] = isPasswordStrong(std::get<2>(passwords[i]));
    }
}

/// \brief Adds a new password to the saved records.
inline void addPassword(privacy::vector <passwordRecords> &passwords, std::vector<bool> &strengths) {
    privacy::string site{getResponseStr("Enter the name of the site/app: ")};
    // The site name must be non-empty
    if (site.empty()) {
        printColor("\nThe site/app name cannot be blank.", 'r', true, std::cerr);
        return;
    }
    privacy::string username{getResponseStr("Username (leave blank if N/A): ")};

    // Check if the record already exists in the database
    const auto it = std::ranges::lower_bound(passwords, std::tie(site, username, std::ignore),
                                             [](const auto &tuple1, const auto &tuple2) {
                                                 return comparator(tuple1, tuple2);
                                             });

    // If the record already exists, ask the user if they want to update it
    bool update{false};
    if (it != passwords.end() && std::get<0>(*it) == site && std::get<1>(*it) == username) {
        printColor("\nA record with the same site and username already exists.", 'y', true);
        printColor("Do you want to update it? (y/n): ", 'b');
        update = validateYesNo();

        if (!update) return;
    }

    privacy::string password{getSensitiveInfo("Enter the password: ")};

    // The password can't be empty. Give the user 2 more tries to enter a non-empty password
    int attempts{0};
    while (password.empty() && ++attempts < 3) {
        printColor("Password can't be blank. Please try again: ", 'y');
        password = getSensitiveInfo();
    }

    // If the password is still empty, return
    if (password.empty()) {
        printColor("Password can't be blank. Try again later.", 'r', true, std::cerr);
        return;
    }
    // Always warn on weak passwords
    if (!isPasswordStrong(password)) {
        printColor(
                "The password you entered is weak! A password should have at least 8 characters \nand include at least an "
                "uppercase character, a lowercase, a punctuator, \nand a digit.", 'y', true);
        printColor("Please consider using a stronger one.", 'r', true);
    }

    // Update the record if it already exists, else add a new one
    if (update)
        std::get<2>(*it) = password;
    else passwords.emplace_back(site, username, password);

    printColor(std::format("Password {} successfully.", update ? "updated" : "added"), 'g', true);

    // Entries should always be sorted
    std::ranges::sort(passwords, [](const auto &tuple1, const auto &tuple2) {
        return comparator(tuple1, tuple2);
    });

    // Recompute strengths
    computeStrengths(passwords, strengths);
}

/// \brief Generates a random password.
inline void generatePassword(privacy::vector <passwordRecords> &, std::vector<bool> &) {
    int length = getResponseInt("Enter the length of the password to generate: ");

    int tries{0};
    // The password must be at least 8 characters long
    while (length < 8 && ++tries < 3) {
        printColor("A strong password should be at least 8 characters long.", 'y', true);
        printColor(std::format("{}", tries == 2 ? "Last chance:" : "Please try again:"),
                   tries == 2 ? 'r' : 'y');
        length = getResponseInt();
    }
    // The password length must not exceed 256 characters
    if (length > 256) {
        printColor("The password length cannot exceed 256 characters.", 'r', true, std::cerr);
        return;
    }

    if (length < 8) return;

    printColor("Generated password: ", 'c');
    printColor(generatePassword(length), 'g', true);
}

/// \brief Shows all saved passwords.
inline void viewAllPasswords(privacy::vector <passwordRecords> &passwords, std::vector<bool> &strengths) {
    // Check if there are any passwords saved
    if (auto &&constPasswordsRef = std::as_const(passwords); constPasswordsRef.empty()) {
        printColor("You haven't saved any password yet.", 'r', true);
    } else {
        std::cout << "All passwords: (";
        printColor("red is weak", 'r');
        std::cout << ", ";
        printColor("green is strong", 'g');

        std::cout << ")" << std::endl;

        printColor("-----------------------------------------------------", 'w', true);
        // Print all the passwords
        for (std::size_t i = 0; i < constPasswordsRef.size(); ++i) {
            printPasswordDetails(constPasswordsRef[i], strengths[i]);
            printColor("-----------------------------------------------------", 'w', true);
        }
    }
}

/// \brief Handles fuzzy matching for update and deletion of passwords.
void checkFuzzyMatches(auto &iter, privacy::vector <passwordRecords> &records, privacy::string &query) {
    // Fuzzy-match the query against the site names
    const FuzzyMatcher matcher(records | std::ranges::views::elements<0>);

    // If there is a single match, ask the user if they want to update the query
    if (const auto fuzzyMatched{matcher.fuzzyMatch(query, 2)}; fuzzyMatched.size() == 1) {
        const auto &match = fuzzyMatched.at(0);

        printColor("Did you mean '", 'c');
        printColor(match, 'g');
        printColor("'? (y/n):", 'c');

        if (validateYesNo()) {
            // Update the iterator
            iter = std::ranges::lower_bound(records, std::tie(match, "", std::ignore),
                                            [](const auto &lhs, const auto &rhs) noexcept -> bool {
                                                return comparator(lhs, rhs);
                                            });
            query = std::string{match};
        }
    } else if (!fuzzyMatched.empty()) {
        // multiple matches
        printColor("Did you mean one of these?:", 'b', true);
        // Print all the matches
        for (const auto &el: fuzzyMatched) {
            printColor(el, 'g', true);
            printColor("-----------------------------------------", 'b', true);
        }
    }
}

/// \brief Updates a password record.
inline void updatePassword(privacy::vector <passwordRecords> &passwords, std::vector<bool> &strengths) {
    if (passwords.empty()) [[unlikely]] {
        // There is nothing to update
        printColor("No passwords saved yet.", 'r', true, std::cerr);
        return;
    }

    privacy::string site{getResponseStr("Enter the name of the site/app to update: ")};
    if (site.empty()) {
        printColor("\nThe site/app name cannot be blank.", 'r', true, std::cerr);
        return;
    }

    // Search for the site
    auto it = std::ranges::lower_bound(passwords, std::tie(site, "", std::ignore),
                                       [](const auto &tuple1, const auto &tuple2) {
                                           return comparator(tuple1, tuple2);
                                       });
    // Check for fuzzy matches if the site is not found
    if (it == passwords.end() || std::get<0>(*it) != site)
        checkFuzzyMatches(it, passwords, site);

    // Extract all the accounts under the site
    auto matches = std::ranges::equal_range(it, passwords.end(), std::tie(site),
                                            [](const auto &lhs, const auto &rhs) {
                                                // this is consistent with the comparator() used to find the lower bound
                                                return std::get<0>(lhs) < std::get<0>(rhs);
                                            });

    if (!matches.empty()) {
        // site found
        if (matches.size() > 1) {
            // there are multiple accounts under the site
            std::cout << "Found the following usernames for " << std::quoted(site) << ":\n";
            for (const auto &[_, username, pass]: matches)
                printColor(username.empty()
                           ? "'' [no username, reply with a blank to select]"
                           : username, 'c', true);

            privacy::string username{getResponseStr("\nEnter one of the above usernames to update:")};

            // Update the iterator to the desired username
            it = std::ranges::lower_bound(matches, std::tie(site, username, std::ignore),
                                          [](const auto &tuple1, const auto &tuple2) {
                                              return comparator(tuple1, tuple2);
                                          });
            // Exit if the entered username is incorrect
            if (it == matches.end() || std::get<1>(*it) != username) {
                printColor("No such username as '", 'r', false, std::cerr);
                printColor(username, 'y', false, std::cerr);
                printColor("' under ", 'r', false, std::cerr);
                printColor(site, 'c', true, std::cerr);

                return;
            }
        } else it = matches.begin(); // there is only a single match anyway

        // Update the required fields
        privacy::string newUsername;
        const bool updateUsername{validateYesNo("Do you want to change the username? (y/n):")};

        if (updateUsername) {
            newUsername = getResponseStr("Enter the new username (Leave blank to delete the current one):");

            // If the entered username exists, ignore the update
            for (const auto &match: matches) {
                if (newUsername == std::get<1>(match)) {
                    std::cerr << "Username already exists for this site. Try again later." << std::endl;

                    return;
                }
            }
        }

        const privacy::string newPassword{
                getSensitiveInfo("Enter the new password (Leave blank to keep the current one): ")
        };

        // Warn if the password is weak
        if (!newPassword.empty() && !isPasswordStrong(newPassword)) {
            printColor(
                    "The password you entered is weak! A password should have at least 8 characters \nand include at least an "
                    "uppercase character, a lowercase, a punctuator, \nand a digit.", 'y', true);
            printColor("Please consider using a stronger one.", 'r', true);
        }

        // Update the record
        if (updateUsername) std::get<1>(*it) = newUsername;
        if (!newPassword.empty()) std::get<2>(*it) = newPassword;

        if (updateUsername || !newPassword.empty()) {
            // Entries should always be sorted
            std::ranges::sort(passwords, [](const auto &tuple1, const auto &tuple2) {
                return comparator(tuple1, tuple2);
            });

            printColor("Password updated successfully.", 'g', true);

            // Recompute strengths
            computeStrengths(passwords, strengths);
        } else printColor("Password not updated.", 'r', true, std::cerr);
    } else {
        printColor("'", 'r', false, std::cerr);
        printColor(site, 'c', false, std::cerr);
        printColor("' was not found in the saved passwords.", 'r', true, std::cerr);
    }
}

/// \brief Deletes a password record.
inline void deletePassword(privacy::vector <passwordRecords> &passwords, std::vector<bool> &strengths) {
    if (passwords.empty()) {
        printColor("No passwords saved yet.", 'r', true, std::cerr);
        return;
    }

    privacy::string site{getResponseStr("Enter the name of the site/app to delete: ")};
    if (site.empty()) {
        printColor("The site/app name cannot be blank.", 'r', true, std::cerr);
        return;
    }

    // Search for the site
    auto it = std::ranges::lower_bound(passwords, std::tie(site, "", std::ignore),
                                       [](const auto &tuple1, const auto &tuple2) {
                                           return comparator(tuple1, tuple2);
                                       });
    // Check for fuzzy matches if the site is not found
    if (it == passwords.end() || std::get<0>(*it) != site)
        checkFuzzyMatches(it, passwords, site);

    // Extract all the accounts under the site
    auto matches = std::ranges::equal_range(it, passwords.end(), std::tie(site),
                                            [](const auto &lhs, const auto &rhs) {
                                                return std::get<0>(lhs) < std::get<0>(rhs);
                                            });

    if (!matches.empty()) {
        // site found
        if (matches.size() > 1) {
            std::cout << "Found the following usernames for " << std::quoted(site) << ":\n";
            for (const auto &[_, username, pass]: matches)
                printColor(username.empty()
                           ? "'' [no username, reply with a blank to select]"
                           : username, 'c', true);

            privacy::string username{
                    getResponseStr("\nEnter one of the above usernames to delete (Enter \"All\" to delete all):")};

            // Update the iterator
            it = std::ranges::lower_bound(matches, std::tie(site, username, std::ignore),
                                          [](const auto &tuple1, const auto &tuple2) {
                                              return comparator(tuple1, tuple2);
                                          });
            if (it == matches.end() || std::get<1>(*it) != username) { // the entered username is incorrect
                // If the entered username is 'All', delete all the records under the site
                if (username == "All") {
                    passwords.erase(matches.begin(), matches.end());
                    printColor("All records under ", 'g');
                    printColor(site, 'c');
                    printColor(" deleted successfully.", 'g', true);

                    // Recompute strengths
                    computeStrengths(passwords, strengths);

                    return;
                }
                printColor("No such username as '", 'r', false, std::cerr);
                printColor(username, 'y', false, std::cerr);
                printColor("' under ", 'r', false, std::cerr);
                printColor(site, 'c', true, std::cerr);

                return;
            }
        } else it = matches.begin();

        // Delete the entry
        passwords.erase(std::remove(it, passwords.end(), *it), passwords.end());

        // Make sure the entries are sorted
        if (!std::ranges::is_sorted(passwords, [](const auto &tuple1, const auto &tuple2) {
            return comparator(tuple1, tuple2);
        }))
            std::ranges::sort(passwords, [](const auto &tuple1, const auto &tuple2) {
                return comparator(tuple1, tuple2);
            });

        printColor("Password record deleted successfully.", 'g', true);

        // Recompute strengths
        computeStrengths(passwords, strengths);
    } else {
        printColor("'", 'r', false, std::cerr);
        printColor(site, 'c', false, std::cerr);
        printColor("' was not found in the saved passwords.", 'r', true, std::cerr);
    }
}

/// \brief Finds a password record.
inline void searchPasswords(privacy::vector <passwordRecords> &passwords, std::vector<bool> &) {
    if (passwords.empty()) [[unlikely]] {
        // There is nothing to search
        printColor("No passwords saved yet.", 'r', true, std::cerr);
        return;
    }

    privacy::string query{getResponseStr("Enter the name of the site/app: ")};
    // The query must be non-empty
    if (query.empty()) {
        printColor("\nThe search query cannot be blank.", 'r', true, std::cerr);
        return;
    }

    // Use a const reference to protect the passwords from accidental modifications
    auto &&constPasswordsRef = std::as_const(passwords);

    // Look for partial and exact matches
    auto matches = constPasswordsRef | std::ranges::views::filter([&query](const auto &vec) -> bool {
        return std::get<0>(vec).contains(query);
    });

    // Print all the matches
    if (!matches.empty()) [[likely]] {
        std::cout << "All the matches:" << std::endl;

        printColor("------------------------------------------------------", 'm', true);
        for (const auto &el: matches) {
            printPasswordDetails(el);
            printColor("------------------------------------------------------", 'm', true);
        }
    } else {
        printColor(std::format("No matches found for '{}'", query), 'r', true);

        // Fuzzy-match the query against the site names
        const FuzzyMatcher matcher(constPasswordsRef | std::ranges::views::elements<0>);

        // If there is a single match, ask the user if they want to view it
        if (const auto fuzzyMatched{matcher.fuzzyMatch(query, 2)}; fuzzyMatched.size() == 1) {
            const auto &match = fuzzyMatched.at(0);

            printColor("Did you mean '", 'c');
            printColor(match, 'g');
            printColor("'? (y/n):", 'c');

            if (validateYesNo()) {
                auto matched = std::ranges::equal_range(constPasswordsRef, std::tie(match),
                                                        [](const auto &lhs, const auto &rhs) noexcept -> bool {
                                                            return std::get<0>(lhs) < std::get<0>(rhs);
                                                        });
                // print all the records under the match
                if (!matched.empty()) [[likely]] {
                    printColor("-----------------------------------------------------", 'w', true);
                    for (const auto &pass: matched) {
                        printPasswordDetails(pass);
                        printColor("-----------------------------------------------------", 'w', true);
                    }
                }
            } else printColor("Sorry, '" + query + "' not found.", 'r', true);
        } else if (!fuzzyMatched.empty()) {
            // multiple matches
            printColor("Did you mean one of these?:", 'b', true);
            // Print all the matches
            for (const auto &el: fuzzyMatched) {
                printColor(el, 'g', true);
                std::cout << "---------------------------------------" << std::endl;
            }
        }
    }
}

/// \brief Imports passwords from a csv file.
inline void importPasswords(privacy::vector <passwordRecords> &passwords, std::vector<bool> &strengths) {
    const string fileName = getResponseStr("Enter the path to the csv file: ");

    privacy::vector <passwordRecords> imports{importCsv(fileName)};

    if (imports.empty()) {
        printColor("No passwords imported.", 'y', true);
        return;
    }

    // Sort the imported passwords
    std::ranges::sort(imports, [](const auto &tuple1, const auto &tuple2) {
        return comparator(tuple1, tuple2);
    });

    // Remove duplicates from the imported passwords using the erase-remove idiom
    auto dups = std::ranges::unique(imports, [](const auto &lhs, const auto &rhs) noexcept -> bool {
        // the binary predicate should check equivalence, not order
        return std::tie(std::get<0>(lhs), std::get<1>(lhs)) == std::tie(std::get<0>(rhs), std::get<1>(rhs));
    });
    imports.erase(dups.begin(), dups.end());

    // Check if the imported passwords already exist in the database by constructing their set intersection
    privacy::vector <passwordRecords> duplicates;
    duplicates.reserve(imports.size());

    // Find the passwords that already exist in the database
    std::ranges::set_intersection(imports, passwords, std::back_inserter(duplicates),
                                  [](const auto &pw1, const auto &pw2) {
                                      return comparator(pw1, pw2);
                                  });

    privacy::vector <passwordRecords> recordsUnion;
    recordsUnion.reserve(passwords.size() + imports.size());

    bool overwrite{true};

    // If there are duplicates, ask the user if they want to overwrite them
    if (!duplicates.empty()) {
        printColor("Warning: The following passwords already exist in the database:", 'y', true);
        for (const auto &duplicate: duplicates) {
            printPasswordDetails(duplicate);
            printColor("-------------------------------------------------", 'm', true);
        }
        printColor("Do you want to overwrite/update them? (y/n): ", 'b');
        overwrite = validateYesNo();
    }

    const std::size_t initSize{passwords.size()};

    if (overwrite) {
        // According to an unofficial language reference, https://en.cppreference.com/w/cpp/algorithm/ranges/set_union,
        // If some element is found m times in the first range and n times in the second,
        // then all m elements will be copied from the first range to result, preserving order,
        // and then exactly max(n-m, 0) elements will be copied from the second range to result,
        // also preserving order.
        // So, if a record exists in both 'imports' and 'passwords' (it is guaranteed here that such a record
        // can be found only once in each range, as both have been deduplicated),
        // then with 'imports' as the first argument, only 'imports' version will be copied to the result.
        std::ranges::set_union(imports, passwords, std::back_inserter(recordsUnion),
                               [](const auto &pw1, const auto &pw2) {
                                   return comparator(pw1, pw2);
                               });
    } else {
        printColor("Warning: Duplicate passwords will not be imported.", 'y', true);

        // 'passwords' now come before 'imports', in accordance with the discussion in the previous branch.
        std::ranges::set_union(passwords, imports, std::back_inserter(recordsUnion),
                               [](const auto &pw1, const auto &pw2) {
                                   return comparator(pw1, pw2);
                               });
    }

    // Update the passwords
    passwords = std::move(recordsUnion);

    // Recompute strengths
    computeStrengths(passwords, strengths);

    if (auto imported = overwrite ? imports.size() : passwords.size() - initSize; std::cmp_greater(imported, 0))
        printColor(std::format("Imported {} passwords successfully.", imported), 'g', true);
    else printColor("Passwords not imported.", 'r', true);
}

/// \brief Exports passwords to a csv file.
inline void exportPasswords(privacy::vector <passwordRecords> &passwords, std::vector<bool> &) {
    auto &&passwordsConstRef = std::as_const(passwords);

    if (passwordsConstRef.empty()) [[unlikely]] {
        printColor("No passwords saved yet.", 'r', true, std::cerr);
        return;
    }
    const string fileName = getResponseStr("Enter the path to save the file (leave blank for default): ");

    // Export the passwords to a csv file
    if (const bool exported = fileName.empty() ? exportCsv(passwordsConstRef) : exportCsv(passwordsConstRef, fileName);
            exported)
        [[likely]]
                // Warn the user about the security risk
                printColor("WARNING: The exported file contains all your passwords in plain text."
                           "\nPlease delete it securely after use.", 'r', true);
    else printColor("Passwords not exported.", 'r', true, std::cerr);
}

/// \brief Analyzes the saved passwords for weak passwords and password reuse.
inline void analyzePasswords(privacy::vector <passwordRecords> &passwords, std::vector<bool> &strengths) {
    if (passwords.empty()) {
        printColor("No passwords to analyze.", 'r', true);
        return;
    }

    const auto total = passwords.size();
    auto &&constPasswordsRef = std::as_const(passwords);

    // Analyze the passwords
    std::cout << "Analyzing passwords..." << std::endl;

    // Scan for weak passwords
    privacy::vector <passwordRecords> weakPasswords;
    weakPasswords.reserve(total);

    for (std::size_t i = 0; i < passwords.size(); ++i) {
        if (!strengths[i])
            weakPasswords.emplace_back(passwords[i]);
    }

    // Check for reused passwords
    std::unordered_map<privacy::string, std::unordered_set<privacy::string> > passwordMap;
    for (const auto &record: constPasswordsRef) {
        const auto &site = std::get<0>(record);
        const auto &password = std::get<2>(record);

        // Add the site to the set of sites that use the password
        passwordMap[password].insert(site);
    }

    // Print the weak passwords
    auto weak{weakPasswords.size()};
    if (!weakPasswords.empty()) [[likely]] {
        printColor(std::format("Found {} account{} with weak passwords:", weak, weak == 1 ? "" : "s"), 'r', true);
        printColor("------------------------------------------------------", 'r', true);
        for (const auto &password: weakPasswords) {
            printPasswordDetails(password);
            printColor("------------------------------------------------------", 'r', true);
        }
        printColor(std::format("Please change the weak passwords above. "
                               "\nYou can use the 'generate password' option to generate strong passwords.\n"), 'r',
                   true);
    } else printColor("No weak passwords found. Keep it up!\n", 'g', true);

    // Find reused passwords
    using PasswordSites = std::pair<std::string, std::unordered_set<privacy::string> >;
    std::multimap<std::size_t, PasswordSites, std::greater<> > countMap;

    for (const auto &[password, sites]: passwordMap) {
        if (const auto &x = sites.size(); x > 1) {
            countMap.insert(std::make_pair(x, PasswordSites(password, sites)));
        }
    }

    // Print reused passwords in descending order of counts
    std::size_t reused{0};
    for (const auto &[count, password_sites]: countMap) {
        printColor("Password '", 'y');
        printColor(password_sites.first, 'r');
        printColor(std::format("' is reused on {} sites:", count), 'y', true);
        for (const auto &site: password_sites.second)
            printColor(site + "\n", 'm');

        std::cout << std::endl;
        ++reused;
    }

    // Print summary
    if (reused) {
        printColor(std::format("{} password{} been reused.", reused,
                               reused == 1 ? " has" : "s have"), 'r', true);
    } else printColor("Nice!! No password reuse detected.", 'g', true);

    printColor(std::format("{} use unique passwords to minimize the impact of their compromise.",
                           reused ? "Please" : "Always"), reused ? 'r' : 'c', true);

    // Print the statistics
    std::cout << "\nTotal passwords: " << total << std::endl;
    if (weak > 0) [[likely]] {
        const char col{std::cmp_greater(weak, total / 4) ? 'r' : 'y'};

        printColor(std::format("{}% of your passwords are weak.",
                               std::round(static_cast<double>(weak) / static_cast<double>(total) * 100 * 100) /
                               100), col, true);
    } else printColor("All your passwords are strong. Keep it up!", 'g', true);
}

/// \brief A simple, minimalistic password manager.
/// \throws std::runtime_error if the primary password is incorrect after 3 attempts.
void passwordManager() {
    privacy::string encryptionKey;
    std::string passwordFile{DefaultPasswordFile};
    bool newSetup{false};

    // Reserve 32 bytes for the primary key.
    encryptionKey.reserve(32);

    // Check if the password file exists
    if (!fs::exists(passwordFile) || !fs::is_regular_file(passwordFile) || fs::is_empty(passwordFile)) {
        auto [path, pass] = initialSetup();

        // If both path and pass are empty, the user wants to exit
        if (path.empty() && pass.empty()) return;

        // The user provided a new primary password
        if (path.empty()) [[likely]] {
            encryptionKey = pass;
            newSetup = true;
        } else {
            // the user pointed us to an existing password records
            passwordFile = path;
        }
    }

    privacy::vector <passwordRecords> passwords;

    if (!newSetup) {
        // preprocess the passwordFile
        const privacy::string pwHash = getHash(passwordFile);

        int attempts{0};
        bool isCorrect;

        // Get the primary password
        do {
            encryptionKey = getSensitiveInfo("Enter the primary password: ");
            isCorrect = verifyPassword(encryptionKey, pwHash);
            if (!isCorrect && attempts < 2)
                printColor("Wrong password, please try again.", 'r', true, std::cerr);
        } while (!isCorrect && ++attempts < 3);

        // If the password is still incorrect, exit
        if (!isCorrect) {
            throw std::runtime_error("3 incorrect password attempts.");
        }

        // Load the saved passwords
        printColor("Decrypting passwords...", 'c', true);
        passwords = loadPasswords(passwordFile, encryptionKey);
    }

    // Sort the existing passwords, if any.
    std::ranges::sort(passwords, [](const auto &tuple1, const auto &tuple2) {
        return comparator(tuple1, tuple2);
    });

    // Assess the passwords' strength
    std::vector<bool> passwordStrength(passwords.size(), false);
    for (std::size_t i = 0; i < passwords.size(); ++i) {
        passwordStrength[i] = isPasswordStrong(std::get<2>(passwords[i]));
    }

    // A map of choices and their corresponding functions
    std::unordered_map<int, void (*)(privacy::vector <passwordRecords> &, std::vector<bool> &)> choices = {
            {1, addPassword},
            {2, updatePassword},
            {3, deletePassword},
            {4, viewAllPasswords},
            {5, searchPasswords},
            {6, generatePassword},
            {7, analyzePasswords},
            {8, importPasswords},
            {9, exportPasswords}
    };
    // A fast, lightweight random number generator
    std::minstd_rand gen(std::random_device{}()); // seed the generator
    std::uniform_int_distribution<int> dist(0, 6); // define the range

    while (true) {
        // Colors to use for the menu
        constexpr auto colors = "rgbymcw";
        auto color = colors[dist(gen)];

        printColor("-------------------------------------------", color, true);
        std::cout << "1.  Add new password\n";
        std::cout << "2.  Update password\n";
        std::cout << "3.  Delete password\n";
        std::cout << "4.  View all passwords\n";
        std::cout << "5.  Search passwords\n";
        std::cout << "6.  Generate Password\n";
        std::cout << "7.  Analyze passwords\n";
        std::cout << "8.  Import passwords\n";
        std::cout << "9.  Export passwords\n";
        std::cout << "10. Change the primary Password\n";
        std::cout << "11. Save and Exit\n";
        printColor("-------------------------------------------", color, true);

        try {
            int choice = getResponseInt("Enter your choice: ");

            if (auto iter = choices.find(choice); iter != choices.end())
                iter->second(passwords, passwordStrength);
            else if (choice == 10) {
                if (changeMasterPassword(encryptionKey))
                    printColor("Master password changed successfully.", 'g', true);
                else printColor("Master password not changed.", 'r', true, std::cerr);
            } else if (choice == 11)
                break;
            else printColor("Invalid choice!", 'r', true, std::cerr);
        } catch (const std::exception &ex) {
            printColor(ex.what(), 'r', true, std::cerr);
        } catch (...) { throw std::runtime_error("An error occurred."); }
    }

    std::cout << "saving passwords.." << std::endl;

    // Create the password file if it doesn't exist
    if (!fs::exists(DefaultPasswordFile)) {
        std::error_code ec;
        if (const auto home{getHomeDir()}; fs::exists(home))
            fs::create_directory(home + "/.privacyShield", home, ec);
        if (ec) {
            printColor(std::format("Failed to create '{}': ", DefaultPasswordFile), 'y', false, std::cerr);
            printColor(ec.message(), 'r', true, std::cerr);
        }
    }
    // Save the passwords
    if (savePasswords(passwords, DefaultPasswordFile, encryptionKey))
        printColor("Passwords saved successfully.", 'g', true);
    else printColor("Passwords not saved!", 'r', true, std::cerr);
}
