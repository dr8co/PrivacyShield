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

#include <iostream>
#include <random>
#include <fstream>
#include <filesystem>
#include <format>
#include <algorithm>
#include <thread>
#include <unistd.h>
#include <sodium.h>

import utils;
import encryption;
import secureAllocator;

module passwordManager;

namespace fs = std::filesystem;

/// \brief Checks the strength of a password.
/// \param password the password to process.
/// \return True if the password is strong, False otherwise.
bool isPasswordStrong(const privacy::string &password) noexcept {
    // Check the length
    if (password.length() < 8)
        return false;

    // Check for at least one uppercase letter, one lowercase letter, one digit, and one special character.
    bool hasUppercase = false;
    bool hasLowercase = false;
    bool hasDigit = false;
    bool hasPunctuation = false;

    for (const char ch: password) {
        if (std::isupper(ch))
            hasUppercase = true;
        else if (std::islower(ch))
            hasLowercase = true;
        else if (std::isdigit(ch))
            hasDigit = true;
        else if (std::ispunct(ch))
            hasPunctuation = true;

        // Break out of the loop as soon as all conditions are satisfied
        if (hasUppercase && hasLowercase && hasDigit && hasPunctuation)
            return true;
    }

    return false;
}

/// \brief Generates a random password.
/// \param length the length of the password.
/// \return a random password.
/// \throws std::length_error if the password is too short or too long.
privacy::string generatePassword(const int &length) {
    // a password shouldn't be too short, nor too long
    if (length < 8)
        throw std::length_error("Password too short.");
    if (length > 256)
        throw std::length_error("Password too long.");

    // generate from a set of printable ascii characters
    const std::string characters =
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()-=_~+[]{}<>";

    // Seed the Mersenne Twister engine with a random source (ideally non-deterministic)
    std::random_device rd;
    std::mt19937_64 generator(rd());

    // Constant probability minimizes predictability
    std::uniform_int_distribution<int> distribution(0, static_cast<int>(characters.size()) - 1);

    privacy::string password;
    password.reserve(length);

    int trials{0};
    constexpr int maxTrials{100}; // 100 trials to generate a strong password is generous enough

    // Generate a strong password by default
    do {
        password.clear(); // empty the password to reset it to it's initial state
        for (int i = 0; i < length; ++i)
            password += characters[distribution(generator)];

        // If the length is >= 8, it is almost impossible that this loop is infinite,
        // but let's handle that ultra-rare situation anyway
    } while (!isPasswordStrong(password) && ++trials <= maxTrials);

    return password;
}

/// \brief Hashes a password (using Argon2id implementation from Sodium)
/// for verification without having to store the password.
/// \param password the password to hash.
/// \param opsLimit the maximum amount of computations to perform.
/// \param memLimit the maximum amount of RAM in bytes that the function will use.
/// \return a string of the password hash and it's associated data.
/// \throws std::runtime_error if the password hashing fails.
privacy::string
hashPassword(const privacy::string &password, const std::size_t &opsLimit, const std::size_t &memLimit) {
    std::array<char, crypto_pwhash_STRBYTES> hashedPassword{};

    if (crypto_pwhash_str
        (hashedPassword.data(), password.c_str(), password.size(),
         opsLimit, memLimit) != 0) {
        throw std::runtime_error("Out of memory for password hashing.");
    }

    return privacy::string{hashedPassword.data()};
}

/// \brief Verifies a password.
/// \param password the password being verified.
/// \param storedHash the hash to verify the password against.
/// \return true if the verification succeeds, else false.
bool verifyPassword(const privacy::string &password, const privacy::string &storedHash) {
    return crypto_pwhash_str_verify(storedHash.c_str(),
                                    password.c_str(),
                                    password.size()) == 0;
}

/// \brief Encrypts/decrypts a range of passwords.
/// \param passwords the password records to encrypt/decrypt.
/// \param key the password to encrypt/decrypt the passwords.
/// \param start the start index of the range.
/// \param end the end index.
/// \param encrypt A boolean value indicating whether to encrypt or decrypt.
/// \throws std::range_error if the range is invalid.
void
encryptDecryptRange(privacy::vector<passwordRecords> &passwords, const privacy::string &key, const std::size_t &start,
                    const std::size_t &end, const bool &encrypt = false) {
    // Check for invalid range
    if (start > end || end > passwords.size())
        throw std::range_error("Invalid range.");

    try {
        // Encrypt/decrypt the password field
        for (std::size_t i = start; i < end; ++i) {
            std::get<2>(passwords[i]) = encrypt
                                            ? encryptStringWithMoreRounds(std::get<2>(passwords[i]), key)
                                            : decryptStringWithMoreRounds(std::string{std::get<2>(passwords[i])},
                                                                          key);
        }
    } catch (const std::exception &ex) {
        printColor(std::format("Error: {}", ex.what()), 'r', true, std::cerr);
        std::exit(1);
    }
}

/// \brief Encrypts/decrypts all fields of a range of password records.
/// \param passwords the password records to encrypt/decrypt.
/// \param key the password to encrypt/decrypt the passwords.
/// \param start the start index of the range.
/// \param end the end index.
/// \param encrypt A boolean value indicating whether to encrypt or decrypt.
/// \throws std::range_error if the range is invalid.
void
encryptDecryptRangeAllFields(privacy::vector<passwordRecords> &passwords, const privacy::string &key,
                             const std::size_t &start,
                             const std::size_t &end, const bool &encrypt = false) {
    if (start > end || end > passwords.size())
        throw std::range_error("Invalid range.");

    try {
        // Encrypt/decrypt all fields
        for (std::size_t i = start; i < end; ++i) {
            std::get<0>(passwords[i]) = encrypt
                                            ? encryptString(std::get<0>(passwords[i]), key)
                                            : decryptString(std::string{std::get<0>(passwords[i])}, key);

            std::get<1>(passwords[i]) = encrypt
                                            ? encryptString(std::get<1>(passwords[i]), key)
                                            : decryptString(std::string{std::get<1>(passwords[i])}, key);

            std::get<2>(passwords[i]) = encrypt
                                            ? encryptString(std::get<2>(passwords[i]), key)
                                            : decryptString(std::string{std::get<2>(passwords[i])}, key);
        }
    } catch (const std::exception &ex) {
        printColor(std::format("Error: {}", ex.what()), 'r', true, std::cerr);
        std::exit(1);
    }
}

/// \brief Encrypts/decrypts passwords concurrently.
/// \param passwordEntries the password records to encrypt/decrypt.
/// \param key the password to encrypt/decrypt the passwords.
/// \param encrypt A boolean value indicating whether to encrypt or decrypt.
/// \param allFields A boolean value indicating whether to encrypt/decrypt all fields or just the password field.
void
encryptDecryptConcurrently(privacy::vector<passwordRecords> &passwordEntries, const privacy::string &key,
                           const bool &encrypt,
                           const bool &allFields) {
    const std::size_t numPasswords = passwordEntries.size();
    const unsigned int numThreads{std::jthread::hardware_concurrency() ? std::jthread::hardware_concurrency() : 8};

    // Divide the password entries among threads
    std::vector<std::jthread> threads;
    const std::size_t passPerThread = numPasswords / numThreads;
    std::size_t start = 0;

    // encrypt/decrypt passwords in parallel
    for (int i = 0; i < static_cast<int>(numThreads - 1); ++i) {
        threads.emplace_back(allFields ? encryptDecryptRangeAllFields : encryptDecryptRange, std::ref(passwordEntries),
                             key, start, start + passPerThread, encrypt);

        start += passPerThread;
    }

    // Account for the division remainder in the last thread
    threads.emplace_back(allFields ? encryptDecryptRangeAllFields : encryptDecryptRange, std::ref(passwordEntries),
                         key, start, passwordEntries.size(), encrypt);

    // Wait for all threads to finish execution
    for (auto &thread: threads)
        thread.join();
}

/// \brief Checks for common errors when reading/writing to a file.
/// \param path the path to the file.
/// \throws std::runtime_error if the file is not a regular file, does not exist, or is a directory.
inline void checkCommonErrors(std::string_view path) {
    std::error_code ec;
    const fs::file_status fileStatus = fs::status(path, ec);
    if (ec)
        throw std::runtime_error(std::format("Could not determine {}'s status: {}.", path, ec.message()));

    if (!exists(fileStatus))
        throw std::runtime_error(std::format("The password file ({}) does not exist.", path));

    if (is_directory(fileStatus))
        throw std::runtime_error(std::format("The path '{}' is a directory.", path));

    if (!is_regular_file(fileStatus))
        throw std::runtime_error(std::format("The password file ({}) is not a regular file.", path));
}

/// \brief Encrypts and then saves passwords to a file.
/// \param passwords a vector of password records.
/// \param filePath the path where the file is saved.
/// \param encryptionKey the key/password to encrypt the passwords in the process.
/// \return True, if successful.
bool savePasswords(privacy::vector<passwordRecords> &passwords, const std::string &filePath,
                   const privacy::string &encryptionKey) {
    std::string tempFile = filePath + "XXXXXX";

    // Create a temporary file
    // If the temporary file couldn't be created, use the original file path
    if (int tmpFileFd = mkstemp(tempFile.data()); tmpFileFd == -1)
        tempFile = filePath;
    else close(tmpFileFd); // Close the file descriptor

    std::ofstream file(tempFile, std::ios::trunc);
    if (!file) {
        try {
            checkCommonErrors(tempFile);
        } catch (const std::exception &ex) {
            std::cerr << ex.what() << std::endl;
        } catch (...) {
        } // Ignore any other exceptions as we're about to exit anyway

        std::cerr << std::format("Failed to open the password file ({}) for writing.\n", tempFile);
        return false;
    }

    file << "PLEASE DO NOT EDIT THIS FILE!" << std::endl;
    file << hashPassword(encryptionKey) << std::endl;

    printColor("Encrypting your passwords...", 'c', true);

    // Encrypt the password field with Serpent
    encryptDecryptConcurrently(passwords, encryptionKey, true, false);

    // Encrypt all fields with AES
    encryptDecryptConcurrently(passwords, encryptionKey, true, true);

    for (const auto &password: passwords) {
        const auto &encryptedSite = std::get<0>(password);
        const auto &encryptedUsername = std::get<1>(password);
        const auto &encryptedPassword = std::get<2>(password);

        if (encryptedSite.empty() || encryptedUsername.empty() || encryptedPassword.empty())
            return false;

        file << encryptedSite << ":" << encryptedUsername << ":" << encryptedPassword << std::endl;
    }
    file.close();

    std::error_code ec;
    // Rename the temporary file to the original file
    fs::rename(tempFile, filePath, ec);

    if (ec) printColor(ec.message(), 'r', true, std::cerr);
    return !ec;
}

/// \brief Loads the encrypted passwords from the disk, and decrypts them.
/// \param filePath path to the password file.
/// \param decryptionKey the key/password to decrypt the passwords.
/// \return decrypted password records.
/// \throws std::runtime_error if the file is empty, or if it couldn't be opened for reading.
privacy::vector<passwordRecords> loadPasswords(const std::string &filePath, const privacy::string &decryptionKey) {
    privacy::vector<passwordRecords> passwords;
    passwords.reserve(1024);

    // Check for common errors
    checkCommonErrors(filePath);
    std::error_code ec;
    if (fs::is_empty(filePath, ec))
        throw std::runtime_error(std::format("The password file ({}) empty.", filePath));
    if (ec) ec.clear();

    std::ifstream file(filePath);
    if (!file)
        throw std::runtime_error(std::format("Failed to open the password file ({}) for reading.", filePath));

    privacy::string line;
    line.reserve(4096); // Pre-allocate space for efficiency

    // Read and discard the first line
    std::getline<char, std::char_traits<char>, privacy::Allocator<char> >(file, line);

    // Read and discard the second line too
    std::getline<char, std::char_traits<char>, privacy::Allocator<char> >(file, line);

    // Read and process the file line by line
    while (std::getline<char, std::char_traits<char>, privacy::Allocator<char> >(file, line)) {
        std::size_t firstDelimiterPos = line.find(':');
        std::size_t secondDelimiterPos = line.find(':', firstDelimiterPos + 1);

        // Badly formatted entry
        if (firstDelimiterPos == privacy::string::npos || secondDelimiterPos == privacy::string::npos) {
            std::cerr << std::format("Invalid password entry: '{}'\n", line);
            continue;
        }

        const auto &website = line.substr(0, firstDelimiterPos);
        const auto &username = line.substr(firstDelimiterPos + 1, secondDelimiterPos - firstDelimiterPos - 1);
        const auto &password = line.substr(secondDelimiterPos + 1);

        // Add the entry to the database
        passwords.emplace_back(website, username, password);
    }

    // Decrypt all fields with AES
    encryptDecryptConcurrently(passwords, decryptionKey, false, true);

    // Decrypt the password field with Serpent
    encryptDecryptConcurrently(passwords, decryptionKey, false, false);

    return passwords;
}

/// \brief Helps the user change the primary password.
/// \param primaryPassword the current primary password.
/// \return True if the password is changed successfully, else false.
bool changeMasterPassword(privacy::string &primaryPassword) {
    const privacy::string oldPassword{getSensitiveInfo("Enter the current primary password: ")};

    // Verify that the old password is correct
    auto masterHash = hashPassword(primaryPassword, crypto_pwhash_OPSLIMIT_INTERACTIVE,
                                   crypto_pwhash_MEMLIMIT_INTERACTIVE);

    if (!verifyPassword(oldPassword, masterHash)) {
        std::cerr << "Password verification failed." << std::endl;
        return false;
    }
    privacy::string newPassword{getSensitiveInfo("Enter the new primary password: ")};
    int count{0};
    while (!isPasswordStrong(newPassword) && ++count < 3) {
        std::cerr
                << "Weak password! Password should have at least 8 characters and include uppercase letters,\n"
                "lowercase letters, special characters and digits" << std::endl;
        newPassword = getSensitiveInfo("Please enter a stronger password: ");
    }

    if (!isPasswordStrong(newPassword)) {
        std::cerr << "The password is still weak. Please try again later." << std::endl;
        return false;
    }

    const privacy::string newPassword2{getSensitiveInfo("Enter the new primary password again: ")};

    // Verify that the new password is correct
    if (!verifyPassword(newPassword2, hashPassword(newPassword, crypto_pwhash_OPSLIMIT_INTERACTIVE,
                                                   crypto_pwhash_MEMLIMIT_INTERACTIVE))) {
        std::cerr << "Passwords do not match." << std::endl;

        return false;
    }
    primaryPassword = newPassword;

    return true;
}

/// \brief Helps with the initial setup of the password manager.
/// \return New primary password and/or path to the password file, whichever is applicable.
std::pair<std::string, privacy::string> initialSetup() noexcept {
    std::pair<std::string, privacy::string> ret{"", ""}; // ret.first = path to file, ret.second = new primary password

    std::cout << "Looks like you don't have any passwords saved yet." << std::endl;

    while (true) {
        const int resp = getResponseInt(
            "1. Initial setup. (Select if you haven't used this program to manage credentials before).\n"
            "2. Enter the path to an existing password file (previously created by this program).\n"
            "3. Exit.\n"
            "select 1, 2, or 3: ");
        if (resp == 1) {
            // Initial setup
            privacy::string pass{getSensitiveInfo("Enter a new primary password: ")};

            int count{0};
            while (!isPasswordStrong(pass) && ++count < 3) {
                const bool last{count == 2};
                printColor(last
                               ? "Last chance: "
                               : "Weak password! The password must be at least 8 characters long and include \nat least an"
                               " uppercase character, a lowercase, a punctuator, and a digit.", last ? 'r' : 'y',
                           !last);
                pass = getSensitiveInfo(last ? "" : "Please enter a stronger password: ");
            }

            if (!isPasswordStrong(pass)) {
                std::cerr << "\n3 incorrect password attempts." << std::endl;
                continue;
            }

            const auto hash = hashPassword(pass, crypto_pwhash_OPSLIMIT_INTERACTIVE,
                                           crypto_pwhash_MEMLIMIT_INTERACTIVE);

            if (const privacy::string pass2{getSensitiveInfo("Enter the password again: ")}; !verifyPassword(
                pass2, hash)) {
                std::cerr << "Password mismatch!" << std::endl;
                continue;
            }

            ret.second = pass;
            break;
        }
        if (resp == 2) {
            // Enter the path to an existing password file
            std::string path = getResponseStr("Enter the path to the file: ");
            if (!(fs::exists(path) && fs::is_regular_file(path))) {
                std::cerr << "That file doesn't exist or is not a regular file." << std::endl;
                continue;
            }

            ret.first = path;
            break;
        }
        if (resp == 3) {
            return ret;
        }
        // Invalid choice
        std::cerr << "Invalid choice. Try again" << std::endl;
    }

    return ret;
}

/// \brief Reads the primary password hash from the password records.
/// \param filePath the path to the file containing the password records (the password file).
/// \return the primary password hash.
/// \throws std::runtime_error if the password file is empty, or if the password hash is not found/is invalid.
privacy::string getHash(const std::string &filePath) {
    checkCommonErrors(filePath);
    if (fs::is_empty(filePath))
        [[unlikely]]
                throw std::runtime_error(std::format("The password file, '{}', is empty.", filePath));

    std::ifstream passFileStream(filePath);

    if (!passFileStream)
        throw std::runtime_error(std::format("Failed to open '{}' for reading.", filePath));

    privacy::string pwHash;
    // Read and discard the first line ('PLEASE DO NOT EDIT THIS FILE')
    std::getline<char, std::char_traits<char>, privacy::Allocator<char> >(passFileStream, pwHash);

    // The hash is on the second line
    std::getline<char, std::char_traits<char>, privacy::Allocator<char> >(passFileStream, pwHash);
    passFileStream.close();

    if (pwHash.empty())
        throw std::runtime_error("The password hash is empty.");

    if (!pwHash.contains("argon")) // Just making sure the read content is the hash we need
        throw std::runtime_error("Invalid password hash in the password file.");

    return pwHash;
}

/// \brief Export the password records to a CSV file.
/// \param records the password records to export.
/// \param filePath the file to export to.
bool exportCsv(const privacy::vector<passwordRecords> &records, const std::string &filePath) {
    fs::path filepath(filePath);
    std::error_code ec;

    // Check if the file path is valid
    if (!fs::path(filepath).has_filename()) {
        printColor(std::format("Invalid file path: {}", filePath), 'r', true, std::cerr);
        return false;
    }

    // Check if the file path is a directory
    if (is_directory(filepath, ec)) {
        // If the file path is a directory, append the default file name to it
        filepath /= "credentials.csv";
    }
    if (ec) ec.clear(); // Don't throw yet, try other checks

    // Check if the file already exists
    if (exists(filepath, ec)) {
        // Check if the file is a regular file
        if (!is_regular_file(filepath)) [[unlikely]] {
            printColor(std::format("The destination file ({}) is not a regular file.", filePath), 'r', true, std::cerr);
            return false;
        }

        if (!validateYesNo("The destination file already exists. Do you want to overwrite it? (y/n):"))
            return false;

        fs::remove(filepath, ec);
        if (ec) {
            std::cerr << "Error removing " << filepath << ": " << ec.message() << std::endl;
            ec.clear();
        }
    }
    if (ec) ec.clear();

    // If the file extension is not .csv or doesn't have an extension, append .csv to it/replace the extension with .csv
    if (filepath.extension() != ".csv")
        filepath.replace_extension(".csv");

    // Open the file for writing
    std::ofstream file(filepath);
    if (!file) {
        printColor(std::format("Failed to open the destination file ({}) for writing.", filePath),
                   'r', true, std::cerr);
        return false;
    }

    file << "site,username,password" << std::endl;

    // Write the records to the file
    for (const auto &record: records)
        file << std::get<0>(record) << "," << std::get<1>(record) << "," << std::get<2>(record) << std::endl;

    file.close();

    // Notify the user that the export was successful
    printColor("Export successful. The file was saved as ", 'g');
    printColor(filepath, 'c', true);
    return true;
}

/// \brief Trims space (whitespace) off the beginning and end of a string.
/// \param str the string to trim.
inline void trim(std::string &str) {
    // Trim the leading space (my IDE finds the w-word offensive)
    std::input_iterator auto it = std::ranges::find_if_not(str.begin(), str.end(),
                                                           [](const char c) { return std::isspace(c); });
    str.erase(str.begin(), it);

    // Trim the trailing space
    it = std::ranges::find_if_not(str.rbegin(), str.rend(), [](const char c) { return std::isspace(c); }).base();
    str.erase(it, str.end());
}

/// \brief Imports password records from a csv file.
/// \param filePath Path to the csv file.
/// \return Imported password records.
/// \note This function expects the csv data to have only three columns: {site, username, password}.
/// The password entry cannot be empty, and either site or username can be empty, but not both.
/// Non-compliant rows will be ignored entirely.
///
/// \throws std::runtime_error if the file couldn't be opened for reading.
privacy::vector<passwordRecords> importCsv(const std::string &filePath) {
    privacy::vector<passwordRecords> passwords;

    checkCommonErrors(filePath);
    bool hasHeader = validateYesNo("Does the file have a header? (Skip the first line?) (y/n): ");

    std::ifstream file(filePath);
    if (!file)
        throw std::runtime_error(std::format("Failed to open the file ({}) for reading.", filePath));

    privacy::string line, value;
    if (hasHeader)
        std::getline<char, std::char_traits<char>, privacy::Allocator<char> >(file,
                                                                              line); // Read and discard the first line

    while (std::getline<char, std::char_traits<char>, privacy::Allocator<char> >(file, line)) {
        privacy::istringstream iss(line);
        privacy::vector<std::string> tokens;

        while (std::getline<char, std::char_traits<char>, privacy::Allocator<char> >(iss, value, ','))
            tokens.emplace_back(value);

        // Trim leading and trailing space from the tokens, including tabs and newlines, if any
        for (auto &token: tokens)
            trim(token);

        if (tokens.size() == 3) {
            // Skip empty passwords
            if (tokens[2].empty()) {
                std::cerr << std::format("Empty password for {}. Entry skipped.\n", tokens[0]);
            } else if (!(tokens[0].empty() && tokens[1].empty())) // Both site & username can't be empty
                passwords.emplace_back(tokens[0], tokens[1], tokens[2]);
        } else
            std::cerr << std::format("Invalid entry skipped: {}\n", line);
    }
    file.close();

    return passwords;
}
