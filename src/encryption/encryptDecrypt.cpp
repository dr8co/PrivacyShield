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

#include <algorithm>
#include <system_error>
#include <utility>
#include <format>
#include <cmath>
#include <unordered_map>
#include <filesystem>
#include <iostream>
#include <gcrypt.h>
#include <sodium.h>

import utils;
import secureAllocator;
import passwordManager;

module encryption;

namespace fs = std::filesystem;

template<typename T>
/// \brief A concept describing a type convertible and comparable with uintmax_t.
/// \tparam T - An integral type.
concept Num = std::integral<T> && std::convertible_to<T, std::uintmax_t> &&
              std::equality_comparable_with<T, std::uintmax_t>;


/// \brief A class to make file sizes more readable.
/// \details Adapted from https://en.cppreference.com/w/cpp/filesystem/file_size
class FormatFileSize {
public:
    explicit FormatFileSize(const Num auto &size) {
        // Default negative values to zero
        if (std::cmp_greater(size, size_))
            size_ = static_cast<std::uintmax_t>(size);
    }

private:
    std::uintmax_t size_{0};

    friend
    std::ostream &operator<<(std::ostream &os, const FormatFileSize ffs) {
        int i{};
        auto mantissa = static_cast<double>(ffs.size_);
        for (; mantissa >= 1024.; mantissa /= 1024., ++i) {
        }
        mantissa = std::ceil(mantissa * 10.) / 10.;
        os << mantissa << "BKMGTPE"[i];
        return i == 0 ? os : os << "B (" << ffs.size_ << ')';
    }
};

/// \brief Available encryption/decryption ciphers.
enum class Algorithms : std::uint_fast8_t {
    AES      = 1 << 0,
    Camellia = 1 << 1,
    Aria     = 1 << 2,
    Serpent  = 1 << 3,
    Twofish  = 1 << 4
};

/// \brief Operation modes: encryption or decryption.
enum class OperationMode : std::uint_fast8_t {
    Encryption = 1,
    Decryption = 2
};

/// \brief An anonymous struct to aid algorithm selection.
constexpr struct {
    const char *const AES = "AES-256-CBC";
    const char *const Camellia = "CAMELLIA-256-CBC";
    const char *const Aria = "ARIA-256-CBC";
    const gcry_cipher_algos Serpent = GCRY_CIPHER_SERPENT256;
    const gcry_cipher_algos Twofish = GCRY_CIPHER_TWOFISH;
} AlgoSelection;

/// \brief Checks for issues with the input file, that may hinder encryption/decryption.
/// \param inFile the input file, to be encrypted/decrypted.
/// \param mode the mode of operation: encryption or decryption.
/// \throws std::invalid_argument if \p mode is invalid.
/// \throws std::runtime_error if the input file does not exist, is a directory,
/// is not a regular file, or is not readable.
inline void checkInputFile(const fs::path &inFile, const OperationMode &mode) {
    if (mode != OperationMode::Encryption && mode != OperationMode::Decryption)
        throw std::invalid_argument("Invalid mode of operation.");

    // Ensure the input file exists and is not a directory
    if (!exists(inFile))
        throw std::runtime_error(std::format("'{}' does not exist.", inFile.string()));
    if (is_directory(inFile))
        throw std::runtime_error(std::format("'{}' is a directory.", inFile.string()));

    // Check if the input file is a regular file and ask for confirmation if it is not
    if (!is_regular_file(inFile)) {
        if (mode == OperationMode::Encryption) {
            // Encryption
            std::cout << inFile.string() << " is not a regular file. \nDo you want to continue? (y/n): ";
            if (!validateYesNo())
                throw std::runtime_error(std::format("{} is not a regular file.", inFile.string()));
        } else
            throw std::runtime_error(
                std::format("{} is not a regular file.", inFile.string())); // Encrypted files are regular
    }
    // Check if the input file is readable
    if (auto file = inFile.string(); !isReadable(file))
        throw std::runtime_error(std::format("{} is not readable.", file));
}

/// \brief Creates non-existing parent directories for a file.
/// \param filePath The file path for which the directory path needs to be created.
/// \return True if the directory path is created successfully or already exists, false otherwise.
inline bool createPath(const fs::path &filePath) noexcept {
    if (filePath.string().empty()) return false; // Can't create empty paths

    std::error_code ec;

    auto absolutePath = weakly_canonical(filePath, ec);
    if (ec) {
        absolutePath = filePath;
        ec.clear();
    }

    if (absolutePath.has_filename())
        absolutePath.remove_filename();

    if (exists(absolutePath, ec)) {
        if (is_directory(absolutePath, ec) || is_regular_file(absolutePath, ec))
            return true;
        return false;
    }

    return create_directories(absolutePath, ec);
}

/// \brief Checks for issues with the output file, that may hinder encryption/decryption.
/// \param inFile the input file, to be encrypted/decrypted.
/// \param outFile the output file, to be saved.
/// \param mode the mode of operation: encryption or decryption.
/// \throws std::invalid_argument if \p mode is invalid.
/// \throws std::runtime_error if the output file is not writable, readable, or there is not enough space to save it.
inline void checkOutputFile(const fs::path &inFile, fs::path &outFile, const OperationMode &mode) {
    if (mode != OperationMode::Encryption && mode != OperationMode::Decryption)
        throw std::invalid_argument("Invalid mode of operation.");

    // Create parent directories, if necessary.
    if (!createPath(outFile))
        throw std::runtime_error("Unable to create destination directory. Check the path");

    if (std::error_code ec; exists(outFile, ec)) {
        // If the output file is not specified, name it appropriately
        if (equivalent(fs::current_path(), outFile)) {
            outFile = inFile;
            if (inFile.extension() == ".enc") {
                outFile.replace_extension("");
            } else if (mode == OperationMode::Encryption) {
                outFile += ".enc";
            } else {
                outFile.replace_extension("");
                outFile += "_decrypted";
                outFile += inFile.extension();
            }
        } else if (is_directory(outFile)) {
            // If the output file is a directory, rename it appropriately.
            if (mode == OperationMode::Encryption) {
                outFile /= inFile.filename();
                outFile += ".enc";
            } else outFile /= inFile.extension() == ".enc" ? inFile.stem() : inFile.filename();
        }
        // If the output file exists, ask for confirmation for overwriting
        if (exists(outFile, ec)) {
            printColor(canonical(outFile).string(), 'b', false, std::cerr);
            printColor(" already exists. \nDo you want to overwrite it? (y/n): ", 'r', false, std::cerr);
            if (!validateYesNo())
                throw std::runtime_error("Operation aborted.");

            // Determine if the output file can be written if it exists
            if (auto file = weakly_canonical(outFile).string(); !(isWritable(file) && isReadable(file)))
                throw std::runtime_error(std::format("{} is not writable/readable.", file));
        }
    }

    // Check if the input and output files are the same
    if (equivalent(inFile, outFile))
        throw std::runtime_error("The input and output files are the same.");

    // Check if there is enough space on the disk to save the output file.
    const auto availableSpace = getAvailableSpace(weakly_canonical(outFile));
    if (const auto fileSize = file_size(inFile); std::cmp_less(availableSpace, fileSize)) {
        printColor("Not enough space to save ", 'r', false, std::cerr);
        printColor(weakly_canonical(outFile).string(), 'c', true, std::cerr);

        printColor("Required:  ", 'y', false, std::cerr);
        printColor(FormatFileSize(fileSize), 'g', true, std::cerr);

        printColor("Available: ", 'y', false, std::cerr);
        printColor(FormatFileSize(availableSpace), 'r', true, std::cerr);

        printColor("\nDo you still want to continue? (y/n):", 'b');
        if (!validateYesNo())
            throw std::runtime_error("Insufficient storage space.");
    }
}

/// \brief Copies the last write time of a file to another.
/// \param srcFile the source file.
/// \param destFile the destination file.
inline void copyLastWrite(const std::string_view srcFile, const std::string_view destFile) noexcept {
    std::error_code ec;
    last_write_time(destFile, fs::last_write_time(srcFile, ec), ec);
}

/// \brief Encrypts/Decrypts a file.
/// \param inputFileName the path to the input file.
/// \param outputFileName the path to the output file.
/// \param password the password to use for encryption/decryption.
/// \param algo the algorithm to use for encryption/decryption.
/// \param mode the mode of operation: encryption or decryption.
void fileEncryptionDecryption(const std::string &inputFileName, const std::string &outputFileName,
                              const privacy::string &password, const Algorithms &algo, const OperationMode &mode) {
    // The mode must be valid: must be either encryption or decryption
    if (mode != OperationMode::Encryption && mode != OperationMode::Decryption) [[unlikely]] {
        printColor("Invalid mode of operation.", 'r', true, std::cerr);
        return;
    }

    try {
        /// Encrypts/decrypts a file based on the passed mode and algorithm.
        auto encryptDecrypt = [&](const std::string &algorithm) -> void {
            if (mode == OperationMode::Encryption) // Encryption
                encryptFile(inputFileName, outputFileName, password, algorithm);
            else // Decryption
                decryptFile(inputFileName, outputFileName, password, algorithm);
        };

        /// Encrypts/decrypts a file using a cipher with more rounds.
        auto encryptDecryptMoreRounds = [&](const gcry_cipher_algos &algorithm) -> void {
            if (mode == OperationMode::Encryption) // Encryption
                encryptFileWithMoreRounds(inputFileName, outputFileName, password, algorithm);
            else // Decryption
                decryptFileWithMoreRounds(inputFileName, outputFileName, password, algorithm);
        };

        // Encrypt/decrypt with the specified algorithm
        switch (algo) {
            case Algorithms::Camellia:
                encryptDecrypt(AlgoSelection.Camellia);
                break;
            case Algorithms::Aria:
                encryptDecrypt(AlgoSelection.Aria);
                break;
            case Algorithms::Serpent:
                encryptDecryptMoreRounds(AlgoSelection.Serpent);
                break;
            case Algorithms::Twofish:
                encryptDecryptMoreRounds(AlgoSelection.Twofish);
                break;
            case Algorithms::AES: [[fallthrough]];
            default:
                encryptDecrypt(AlgoSelection.AES);
        }

        // If we reach here, the operation was successful
        auto pre = mode == OperationMode::Encryption ? "En" : "De";
        printColor(std::format("{}cryption completed successfully. \n{}crypted file saved as ", pre, pre), 'g');
        printColor(outputFileName, 'b', true);

        // Preserve file permissions
        if (!copyFilePermissions(inputFileName, outputFileName))
            [[unlikely]]
                    printColor(std::format("Check the permissions of the {}crypted file.", pre), 'm', true);

        // Try to preserve the time of last modification
        copyLastWrite(inputFileName, outputFileName);
    } catch (const std::exception &ex) {
        printColor(std::format("Error: {}", ex.what()), 'r', true, std::cerr);
    }
}

/// \brief Encrypts and decrypts files.
void encryptDecrypt() {
    // I'm using hashmaps as an alternative to multiple if-else statements
    const std::unordered_map<int, Algorithms> algoChoice = {
        {0, Algorithms::AES}, // Default
        {1, Algorithms::AES},
        {2, Algorithms::Camellia},
        {3, Algorithms::Aria},
        {4, Algorithms::Serpent},
        {5, Algorithms::Twofish}
    };

    const std::unordered_map<Algorithms, std::string_view> algoDescription = {
        {Algorithms::AES, "256-bit AES in CBC mode"},
        {Algorithms::Camellia, "256-bit Camellia in CBC mode"},
        {Algorithms::Aria, "256-bit Aria in CBC mode"},
        {Algorithms::Serpent, "256-bit Serpent in CTR mode"},
        {Algorithms::Twofish, "256-bit Twofish in CTR mode"}
    };

    while (true) {
        std::cout << "-------------";
        printColor(" file encryption/decryption utility ", 'c');
        std::cout << "-------------\n";
        printColor("1. Encrypt a file\n", 'g');
        printColor("2. Decrypt a file\n", 'm');
        printColor("3. Exit\n", 'r');
        std::cout << "--------------------------------------------------------------" << std::endl;

        if (const int choice = getResponseInt("Enter your choice: "); choice == 1 || choice == 2) {
            try {
                std::string pre = choice == 1 ? "En" : "De"; // the prefix string
                std::string pre_l{pre}; // the prefix in lowercase

                // Transform the prefix to lowercase
                std::ranges::transform(pre_l.begin(), pre_l.end(), pre_l.begin(),
                                       [](const unsigned char c) -> unsigned char {
                                           return std::tolower(c);
                                       });

                printColor(std::format("Enter the path to the file to {}crypt:", pre_l), 'c', true);
                std::string inputFile = getResponseStr();

                // Remove the trailing directory separator
                // ('\\' is considered as well in case the program is to be extended to Windows)
                if ((inputFile.ends_with('/') || inputFile.ends_with('\\')) && inputFile.size() > 1)
                    inputFile.erase(inputFile.size() - 1);

                fs::path inputPath(inputFile);
                if (!inputPath.is_absolute()) // The path should be absolute
                    inputPath = fs::current_path() / inputPath;
                checkInputFile(inputPath, static_cast<OperationMode>(choice));

                printColor(std::format("Enter the path to save the {}crypted file "
                                       "\n(or leave it blank to save it in the same directory):",
                                       pre_l), 'c', true);

                fs::path outputPath{getResponseStr()};
                if (!outputPath.is_absolute()) // If the path is not absolute
                    outputPath = fs::current_path() / outputPath;
                checkOutputFile(inputPath, outputPath, static_cast<OperationMode>(choice));

                std::cout << "Choose a cipher (All are 256-bit):\n";
                printColor("1. Advanced Encryption Standard (AES)\n", 'b');
                printColor("2. Camellia\n", 'c');
                printColor("3. Aria\n", 'g');
                printColor("4. Serpent\n", 'y');
                printColor("5. Twofish\n", 'm');

                std::cout << "Leave blank to use the default (AES)" << std::endl;

                int algo = getResponseInt();
                if (algo < 0 || algo > 5) {
                    // 0 is default (AES)
                    printColor("Invalid choice!", 'r', true, std::cerr);
                    continue;
                }

                const auto it = algoChoice.find(algo);
                auto cipher = it != algoChoice.end() ? it->second : Algorithms::AES;

                privacy::string password{getSensitiveInfo("Enter the password: ")};

                // Confirm the password before encryption
                if (choice == 1) {
                    int tries{0};
                    while (password.empty() && ++tries < 3) {
                        printColor("Please avoid empty or weak passwords. Please try again.", 'r', true, std::cerr);
                        password = getSensitiveInfo("Enter the password: ");
                    }

                    if (tries >= 3)
                        throw std::runtime_error("Empty encryption password.");

                    const privacy::string password2{getSensitiveInfo("Enter the password again: ")};

                    if (!verifyPassword(password2, hashPassword(password, crypto_pwhash_OPSLIMIT_INTERACTIVE,
                                                                crypto_pwhash_MEMLIMIT_INTERACTIVE))) {
                        printColor("Passwords do not match.", 'r', true, std::cerr);
                        continue;
                    }
                }
                printColor(std::format("{}crypting ", pre), 'g');
                printColor(canonical(inputPath).string(), 'b');
                printColor(" with ", 'g');
                printColor(algoDescription.find(cipher)->second, 'c');
                printColor("...", 'g', true);

                fileEncryptionDecryption(canonical(inputPath).string(), weakly_canonical(outputPath).string(),
                                         password, cipher, static_cast<OperationMode>(choice));
                std::cout << std::endl;
            } catch (const std::exception &ex) {
                printColor("Error: ", 'y', false, std::cerr);
                printColor(ex.what(), 'r', true, std::cerr);
                std::cerr << std::endl;
            }
        } else if (choice == 3) break;
        else printColor("Invalid choice!", 'r', true, std::cerr);
    }
}
