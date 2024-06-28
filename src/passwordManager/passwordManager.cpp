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
import mimallocSTL;

module passwordManager;

namespace fs = std::filesystem;
using string = miSTL::string;
const string DefaultPasswordFile = getHomeDir() + "/.privacyShield/passwords";

/// \brief A binary predicate for searching, sorting, and deduplication of the password records,
/// based on the site and username members of a password tuple.
/// \param lhs a password record tuple.
/// \param rhs another record to be compared with lhs.
/// \return true if lhs is less than (i.e. is ordered before) rhs, else false.
bool constexpr comparator
#if __clang__ || __GNUC__
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
        printColoredOutput('c', "{}", site);
    }

    if (!username.empty()) {
        std::cout << "\nUsername: ";
        printColoredOutput('b', "{}", username);
    }
    // Highlight a weak password
    std::cout << "\nPassword: ";
    printColoredOutputln(isStrong ? 'g' : 'r', "{}", pass);
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
#if __clang__ || __GNUC__
[[gnu::always_inline]]
#endif
(const privacy::vector<passwordRecords> &passwords, miSTL::vector<bool> &pwStrengths) {
    pwStrengths.resize(passwords.size());
    for (std::size_t i = 0; i < passwords.size(); ++i) {
        pwStrengths[i] = isPasswordStrong(std::get<2>(passwords[i]));
    }
}

/// \brief Adds a new password to the saved records.
void addPassword(privacy::vector<passwordRecords> &passwords, miSTL::vector<bool> &strengths) {
    privacy::string site{getResponseStr("Enter the name of the site/app: ")};
    // The site name must be non-empty
    if (site.empty()) {
        printColoredErrorln('r', "\nThe site/app name cannot be blank.");
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
        printColoredOutput('y', "\nA record with the same site and username already exists.");
        printColoredOutput('b', "Do you want to update it? (y/n):");
        update = validateYesNo();

        if (!update) return;
    }

    privacy::string password{getSensitiveInfo("Enter the password: ")};

    // The password can't be empty. Give the user 2 more tries to enter a non-empty password
    int attempts{0};
    while (password.empty() && ++attempts < 3) {
        printColoredOutput('y', "Password can't be blank. Please try again: ");
        password = getSensitiveInfo();
    }

    // If the password is still empty, return
    if (password.empty()) {
        printColoredErrorln('r', "Password can't be blank. Try again later.");
        return;
    }
    // Always warn on weak passwords
    if (!isPasswordStrong(password)) {
        printColoredOutputln('y',
                             "The password you entered is weak! A password should have at least 8 characters \nand include at least an "
                             "uppercase character, a lowercase, a punctuator, \nand a digit.");
        printColoredOutputln('r', "Please consider using a stronger one.");
    }

    // Update the record if it already exists, else add a new one
    if (update)
        std::get<2>(*it) = password;
    else passwords.emplace_back(site, username, password);

    printColoredOutputln('g', "Password {} successfully.", update ? "updated" : "added");

    // Entries should always be sorted
    std::ranges::sort(passwords, [](const auto &tuple1, const auto &tuple2) {
        return comparator(tuple1, tuple2);
    });

    // Recompute strengths
    computeStrengths(passwords, strengths);
}

/// \brief Generates a random password.
void generatePassword(privacy::vector<passwordRecords> &, miSTL::vector<bool> &) {
    int length = getResponseInt("Enter the length of the password to generate: ");

    int tries{0};
    // The password must be at least 8 characters long
    while (length < 8 && ++tries < 3) {
        printColoredOutputln('y', "A strong password should be at least 8 characters long.");
        printColoredOutputln(tries == 2 ? 'r' : 'y', "{}", tries == 2 ? "Last chance:" : "Please try again:");
        length = getResponseInt();
    }
    // The password length must not exceed 256 characters
    if (length > 256) {
        printColoredErrorln('r', "The password length cannot exceed 256 characters.");
        return;
    }

    if (length < 8) return;

    printColoredOutput('c', "Generated password: ");
    printColoredOutputln('g', "{}", generatePassword(length));
}

/// \brief Shows all saved passwords.
void viewAllPasswords(privacy::vector<passwordRecords> &passwords, miSTL::vector<bool> &strengths) {
    // Check if there are any passwords saved
    if (auto &&constPasswordsView = std::ranges::views::as_const(passwords); constPasswordsView.empty()) {
        printColoredOutputln('r', "You haven't saved any password yet.");
    } else {
        std::cout << "All passwords: (";
        printColoredOutput('r', "red is weak");
        std::cout << ", ";
        printColoredOutput('g', "green is strong");

        std::cout << ")" << std::endl;

        printColoredOutputln('w', "-----------------------------------------------------");
        // Print all the passwords
        for (std::size_t i = 0; i < constPasswordsView.size(); ++i) {
            printPasswordDetails(constPasswordsView[i], strengths[i]);
            printColoredOutputln('w', "-----------------------------------------------------");
        }
    }
}

/// \brief Handles fuzzy matching for update and deletion of passwords.
void checkFuzzyMatches(auto &iter, privacy::vector<passwordRecords> &records, privacy::string &query) {
    // Fuzzy-match the query against the site names
    const FuzzyMatcher matcher(records | std::ranges::views::elements<0>);

    // If there is a single match, ask the user if they want to update the query
    if (const auto fuzzyMatched{matcher.fuzzyMatch(query, 2)}; fuzzyMatched.size() == 1) {
        const auto &match = fuzzyMatched.at(0);

        printColoredOutput('c', "Did you mean '");
        printColoredOutput('g', "{}", match);
        printColoredOutput('c', "'? (y/n):");

        if (validateYesNo()) {
            // Update the iterator
            iter = std::ranges::lower_bound(records, std::tie(match, "", std::ignore),
                                            [](const auto &lhs, const auto &rhs) noexcept -> bool {
                                                return comparator(lhs, rhs);
                                            });
            query = miSTL::string{match};
        }
    } else if (!fuzzyMatched.empty()) {
        // multiple matches
        printColoredOutputln('b', "Did you mean one of these?:");
        // Print all the matches
        for (const auto &el: fuzzyMatched) {
            printColoredOutputln('g', "{}", el);
            printColoredOutputln('b', "-----------------------------------------");
        }
    }
}

/// \brief Updates a password record.
void updatePassword(privacy::vector<passwordRecords> &passwords, miSTL::vector<bool> &strengths) {
    if (passwords.empty()) [[unlikely]] {
        // There is nothing to update
        printColoredErrorln('r', "No passwords saved yet.");
        return;
    }

    privacy::string site{getResponseStr("Enter the name of the site/app to update: ")};
    if (site.empty()) {
        printColoredErrorln('r', "\nThe site/app name cannot be blank.");
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
    if (auto matches = std::ranges::equal_range(it, passwords.end(), std::tie(site),
                                                [](const auto &lhs, const auto &rhs) {
                                                    // this is consistent with the comparator() used to find the lower bound
                                                    return std::get<0>(lhs) < std::get<0>(rhs);
                                                }); !matches.empty()) {
        // site found
        if (matches.size() > 1) {
            // there are multiple accounts under the site
            std::cout << "Found the following usernames for " << std::quoted(site) << ":\n";
            for (const auto &[_, username, pass]: matches)
                printColoredOutputln('c', "{}", username.empty()
                                                    ? "'' [no username, reply with a blank to select]"
                                                    : username);

            privacy::string username{getResponseStr("\nEnter one of the above usernames to update:")};

            // Update the iterator to the desired username
            it = std::ranges::lower_bound(matches, std::tie(site, username, std::ignore),
                                          [](const auto &tuple1, const auto &tuple2) {
                                              return comparator(tuple1, tuple2);
                                          });
            // Exit if the entered username is incorrect
            if (it == matches.end() || std::get<1>(*it) != username) {
                printColoredError('r', "No such username as '");
                printColoredError('y', "{}", username);
                printColoredError('r', "' under ");
                printColoredErrorln('c', "{}", site);

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
            printColoredOutputln('y',
                                 "The password you entered is weak! A password should have at least 8 characters \nand include at least an "
                                 "uppercase character, a lowercase, a punctuator, \nand a digit.");
            printColoredOutputln('r', "Please consider using a stronger one.");
        }

        // Update the record
        if (updateUsername) std::get<1>(*it) = newUsername;
        if (!newPassword.empty()) std::get<2>(*it) = newPassword;

        if (updateUsername || !newPassword.empty()) {
            // Entries should always be sorted
            std::ranges::sort(passwords, [](const auto &tuple1, const auto &tuple2) {
                return comparator(tuple1, tuple2);
            });

            printColoredOutputln('g', "Password updated successfully.");

            // Recompute strengths
            computeStrengths(passwords, strengths);
        } else printColoredErrorln('r', "Password not updated.");
    } else {
        printColoredError('r', "'");
        printColoredError('c', "{}", site);
        printColoredErrorln('r', "' was not found in the saved passwords.");
    }
}

/// \brief Deletes a password record.
void deletePassword(privacy::vector<passwordRecords> &passwords, miSTL::vector<bool> &strengths) {
    if (passwords.empty()) {
        printColoredErrorln('r', "No passwords saved yet.");
        return;
    }

    privacy::string site{getResponseStr("Enter the name of the site/app to delete: ")};
    if (site.empty()) {
        printColoredErrorln('r', "The site/app name cannot be blank.");
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
    if (auto matches = std::ranges::equal_range(it, passwords.end(), std::tie(site),
                                                [](const auto &lhs, const auto &rhs) {
                                                    return std::get<0>(lhs) < std::get<0>(rhs);
                                                }); !matches.empty()) {
        // site found
        if (matches.size() > 1) {
            std::cout << "Found the following usernames for " << std::quoted(site) << ":\n";
            for (const auto &[_, username, pass]: matches)
                printColoredOutputln('c', "{}", username.empty()
                                                    ? "'' [no username, reply with a blank to select]"
                                                    : username);

            privacy::string username{
                getResponseStr("\nEnter one of the above usernames to delete (Enter \"All\" to delete all):")
            };

            // Update the iterator
            it = std::ranges::lower_bound(matches, std::tie(site, username, std::ignore),
                                          [](const auto &tuple1, const auto &tuple2) {
                                              return comparator(tuple1, tuple2);
                                          });
            if (it == matches.end() || std::get<1>(*it) != username) {
                // the entered username is incorrect
                // If the entered username is 'All', delete all the records under the site
                if (username == "All") {
                    passwords.erase(matches.begin(), matches.end());
                    printColoredOutput('g', "All records under ");
                    printColoredOutput('c', "{}", site);
                    printColoredOutputln('g', " deleted successfully.");

                    // Recompute strengths
                    computeStrengths(passwords, strengths);

                    return;
                }
                printColoredError('r', "No such username as '");
                printColoredError('y', "{}", username);
                printColoredError('r', "' under ");
                printColoredErrorln('c', "{}", site);

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

        printColoredOutputln('g', "Password record deleted successfully.");

        // Recompute strengths
        computeStrengths(passwords, strengths);
    } else {
        printColoredError('r', "'");
        printColoredError('c', "{}", site);
        printColoredErrorln('r', "' was not found in the saved passwords.");
    }
}

/// \brief Finds a password record.
void searchPasswords(privacy::vector<passwordRecords> &passwords, miSTL::vector<bool> &) {
    if (passwords.empty()) [[unlikely]] {
        // There is nothing to search
        printColoredErrorln('r', "No passwords saved yet.");
        return;
    }

    privacy::string query{getResponseStr("Enter the name of the site/app: ")};
    // The query must be non-empty
    if (query.empty()) {
        printColoredErrorln('r', "\nThe search query cannot be blank.");
        return;
    }

    // Use a const reference to protect the passwords from accidental modifications
    auto &&constPasswordsView = std::ranges::views::as_const(passwords);

    // Look for partial and exact matches
    if (auto matches = constPasswordsView | std::ranges::views::filter([&query](const auto &vec) -> bool {
        return std::get<0>(vec).contains(query);
    }); !matches.empty()) [[likely]] {
        // Print all the matches
        std::cout << "All the matches:" << std::endl;

        printColoredOutputln('m', "------------------------------------------------------");
        for (const auto &el: matches) {
            printPasswordDetails(el, isPasswordStrong(std::get<2>(el)));
            printColoredOutputln('m', "------------------------------------------------------");
        }
    } else {
        printColoredErrorln('r', "No matches found for '{}'", query);

        // Fuzzy-match the query against the site names
        const FuzzyMatcher matcher(constPasswordsView | std::ranges::views::elements<0>);

        // If there is a single match, ask the user if they want to view it
        if (const auto fuzzyMatched{matcher.fuzzyMatch(query, 2)}; fuzzyMatched.size() == 1) {
            const auto &match = fuzzyMatched.at(0);

            printColoredOutput('c', "Did you mean '");
            printColoredOutput('g', "{}", match);
            printColoredOutput('c', "'? (y/n):");

            if (validateYesNo()) {
                // print all the records under the match
                if (auto matched = std::ranges::equal_range(constPasswordsView, std::tie(match),
                                                            [](const auto &lhs, const auto &rhs) noexcept -> bool {
                                                                return std::get<0>(lhs) < std::get<0>(rhs);
                                                            }); !matched.empty()) [[likely]] {
                    printColoredOutputln('w', "-----------------------------------------------------");
                    for (const auto &pass: matched) {
                        printPasswordDetails(pass, isPasswordStrong(std::get<2>(pass)));
                        printColoredOutputln('w', "-----------------------------------------------------");
                    }
                }
            } else printColoredErrorln('r', "Sorry, '{}' not found.", query);
        } else if (!fuzzyMatched.empty()) {
            // multiple matches
            printColoredOutputln('b', "Did you mean one of these?:");
            // Print all the matches
            for (const auto &el: fuzzyMatched) {
                printColoredOutput('g', "{}", el);
                std::cout << "---------------------------------------" << std::endl;
            }
        }
    }
}

/// \brief Imports passwords from a csv file.
void importPasswords(privacy::vector<passwordRecords> &passwords, miSTL::vector<bool> &strengths) {
    const fs::path fileName = getFilesystemPath("Enter the path to the csv file: ");

    privacy::vector<passwordRecords> imports{importCsv(fileName)};

    if (imports.empty()) {
        printColoredOutputln('y', "No passwords imported.");
        return;
    }

    // Sort the imported passwords
    std::ranges::sort(imports, [](const auto &tuple1, const auto &tuple2) {
        return comparator(tuple1, tuple2);
    });

    // Remove duplicates from the imported passwords using the erase-remove idiom
    auto dups = std::ranges::unique(imports, [](const auto &lhs, const auto &rhs) noexcept -> bool {
        // The binary predicate should check equivalence, not order
        return std::tie(std::get<0>(lhs), std::get<1>(lhs)) == std::tie(std::get<0>(rhs), std::get<1>(rhs));
    });
    imports.erase(dups.begin(), dups.end());

    // Check if the imported passwords already exist in the database by constructing their set intersection
    privacy::vector<passwordRecords> duplicates;
    duplicates.reserve(imports.size());

    // Find the passwords that already exist in the database
    std::ranges::set_intersection(imports, passwords, std::back_inserter(duplicates),
                                  [](const auto &pw1, const auto &pw2) {
                                      return comparator(pw1, pw2);
                                  });

    privacy::vector<passwordRecords> recordsUnion;
    recordsUnion.reserve(passwords.size() + imports.size());

    bool overwrite{true};

    // If there are duplicates, ask the user if they want to overwrite them
    if (!duplicates.empty()) {
        printColoredOutputln('y', "Warning: The following passwords already exist in the database:");
        for (const auto &duplicate: duplicates) {
            printPasswordDetails(duplicate, isPasswordStrong(std::get<2>(duplicate)));
            printColoredOutputln('m', "-------------------------------------------------");
        }
        printColoredOutput('b', "Do you want to overwrite/update them? (y/n): ");
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
        printColoredOutputln('y', "Warning: Duplicate passwords will not be imported.");

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
        printColoredOutputln('g', "Imported {} passwords successfully.", imported);
    else printColoredErrorln('r', "Passwords not imported.");
}

/// \brief Exports passwords to a csv file.
void exportPasswords(privacy::vector<passwordRecords> &passwords, miSTL::vector<bool> &) {
    auto &&constPasswordsView = std::as_const(passwords);

    if (constPasswordsView.empty()) [[unlikely]] {
        printColoredOutputln('r', "No passwords saved yet.");
        return;
    }
    const fs::path fileName = getFilesystemPath("Enter the path to save the file (leave blank for default): ");

    // Export the passwords to a csv file
    if (const bool exported = fileName.string().empty()
                                  ? exportCsv(constPasswordsView)
                                  : exportCsv(constPasswordsView, fileName); exported) [[likely]]
            // Warn the user about the security risk
            printColoredOutputln('r', "WARNING: The exported file contains all your passwords in plain text."
                                 "\nPlease delete it securely after use.");
    else printColoredErrorln('r', "Passwords not exported.");
}

/// \brief Analyzes the saved passwords for weak passwords and password reuse.
void analyzePasswords(privacy::vector<passwordRecords> &passwords, miSTL::vector<bool> &strengths) {
    if (passwords.empty()) {
        printColoredOutputln('r', "No passwords to analyze.");
        return;
    }

    const auto total = passwords.size();
    auto &&constPasswordsView = std::ranges::views::as_const(passwords);

    // Analyze the passwords
    std::cout << "Analyzing passwords..." << std::endl;

    // Scan for weak passwords
    privacy::vector<passwordRecords> weakPasswords;
    weakPasswords.reserve(total);

    for (std::size_t i = 0; i < passwords.size(); ++i) {
        if (!strengths[i])
            weakPasswords.emplace_back(passwords[i]);
    }

    // Check for reused passwords
    miSTL::unordered_map<privacy::string, miSTL::unordered_set<privacy::string> > passwordMap;
    for (const auto &[site, _, password]: constPasswordsView) {
        // Add the site to the set of sites that use the password
        passwordMap[password].insert(site);
    }

    // Print the weak passwords
    auto weak{weakPasswords.size()};
    if (!weakPasswords.empty()) [[likely]] {
        printColoredOutputln('r', "Found {} account{} with weak passwords:", weak, weak == 1 ? "" : "s");
        printColoredErrorln('r', "------------------------------------------------------");
        for (const auto &password: weakPasswords) {
            printPasswordDetails(password);
            printColoredErrorln('r', "------------------------------------------------------");
        }
        printColoredOutputln('r', "Please change the weak passwords above. "
                             "\nYou can use the 'generate password' option to generate strong passwords.");
    } else printColoredOutputln('g', "No weak passwords found. Keep it up!");

    // Find reused passwords
    using PasswordSites = std::pair<miSTL::string, miSTL::unordered_set<privacy::string> >;
    std::multimap<std::size_t, PasswordSites, std::greater<> > countMap;

    for (const auto &[password, sites]: passwordMap) {
        if (const auto &x = sites.size(); x > 1) {
            countMap.insert(std::make_pair(x, PasswordSites(password, sites)));
        }
    }

    // Print reused passwords in descending order of counts
    std::size_t reused{0};
    for (const auto &[count, password_sites]: countMap) {
        printColoredOutput('y', "Password '");
        printColoredOutput('r', "{}", password_sites.first);
        printColoredOutputln('y', "' is reused on {} sites:", count);
        for (const auto &site: password_sites.second)
            printColoredOutputln('m', "{}", site);

        std::cout << std::endl;
        ++reused;
    }

    // Print summary
    if (reused) {
        printColoredOutputln('r', "{} password{} been reused.", reused,
                             reused == 1 ? " has" : "s have");
    } else printColoredOutputln('g', "Nice!! No password reuse detected.");

    printColoredOutputln(reused ? 'r' : 'c', "{} use unique passwords to minimize the impact of their compromise.",
                         reused ? "Please" : "Always");

    // Print the statistics
    std::cout << "\nTotal passwords: " << total << std::endl;
    if (weak > 0) [[likely]] {
        const char col{std::cmp_greater(weak, total / 4) ? 'r' : 'y'};

        printColoredOutputln(col, "{}% of your passwords are weak.",
                             std::round(static_cast<double>(weak) / static_cast<double>(total) * 100 * 100) / 100);
    } else printColoredOutputln('g', "All your passwords are strong. Keep it up!");
}

/// \brief A simple, minimalistic password manager.
/// \throws std::runtime_error if the primary password is incorrect after 3 attempts.
void passwordManager() {
    privacy::string encryptionKey;
    miSTL::string passwordFile{DefaultPasswordFile};
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
            passwordFile = path.c_str();
        }
    }

    privacy::vector<passwordRecords> passwords;

    if (!newSetup) {
        // preprocess the passwordFile
        const privacy::string pwHash = getHash(passwordFile);

        int attempts{0};
        bool isCorrect;

        // Get the primary password
        do {
            encryptionKey = getSensitiveInfo("Enter your primary password: ");
            isCorrect = verifyPassword(encryptionKey, pwHash);
            if (!isCorrect && attempts < 2)
                printColoredErrorln('r', "Wrong password, please try again.");
        } while (!isCorrect && ++attempts < 3);

        // If the password is still incorrect, exit
        if (!isCorrect)
            throw std::runtime_error("3 incorrect password attempts.");

        // Load the saved passwords
        printColoredOutputln('c', "Decrypting passwords...");
        passwords = loadPasswords(passwordFile, encryptionKey);
    }

    // Sort the existing passwords, if any.
    std::ranges::sort(passwords, [](const auto &tuple1, const auto &tuple2) {
        return comparator(tuple1, tuple2);
    });

    // Assess the passwords' strength
    miSTL::vector<bool> passwordStrength(passwords.size(), false);
    for (std::size_t i = 0; i < passwords.size(); ++i) {
        passwordStrength[i] = isPasswordStrong(std::get<2>(passwords[i]));
    }

    // A map of choices and their corresponding functions
    miSTL::unordered_map<int, void (*)(privacy::vector<passwordRecords> &, miSTL::vector<bool> &)> choices = {
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
        const auto color = colors[dist(gen)];

        printColoredOutput(color, "----------------");
        printColoredOutput(colors[dist(gen)], " Password Manager ");
        printColoredOutputln(color, "----------------");

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
        printColoredOutputln(color, "----------------------------------------------");

        try {
            int choice = getResponseInt("Enter your choice: ");

            if (auto iter = choices.find(choice); iter != choices.end())
                iter->second(passwords, passwordStrength);
            else if (choice == 10) {
                if (changePrimaryPassword(encryptionKey))
                    printColoredOutputln('g', "Primary password changed successfully.");
                else printColoredErrorln('r', "Primary password not changed.");
            } else if (choice == 11)
                break;
            else printColoredErrorln('r', "Invalid choice!");
        } catch (const std::exception &ex) {
            printColoredErrorln('r', "{}", ex.what());
        } catch (...) { throw std::runtime_error("An error occurred."); }
    }

    std::cout << "saving passwords.." << std::endl;

    // Create the password file if it doesn't exist
    if (!fs::exists(DefaultPasswordFile)) {
        std::error_code ec;
        if (const auto home{getHomeDir()}; fs::exists(home))
            fs::create_directory(home + "/.privacyShield", home, ec);
        if (ec) {
            printColoredError('y', "Failed to create '{}': ", DefaultPasswordFile);
            printColoredErrorln('r', "{}", ec.message());
        }
    }
    // Save the passwords
    if (savePasswords(passwords, DefaultPasswordFile, encryptionKey))
        printColoredOutputln('g', "Passwords saved successfully.");
    else printColoredErrorln('r', "Passwords not saved!");
}
