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
#include <gcrypt.h>
#include <sodium.h>
#include <print>

import utils;
import secureAllocator;
import passwordManager;

module encryption;

namespace fs = std::filesystem;

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


/// \brief Formats a file size into a human-readable string.
/// \param size The file size as an unsigned integer.
/// \return A string representing the formatted file size.
std::string formatFileSize(const std::uintmax_t &size) {
    int i{};
    auto mantissa = static_cast<double>(size);
    for (; mantissa >= 1024.; mantissa /= 1024., ++i) {
    }
    mantissa = std::ceil(mantissa * 10.) / 10.;
    std::string result = std::to_string(mantissa) + "BKMGTPE"[i];
    return i == 0 ? result : result + "B (" + std::to_string(size) + ')';
}

/// \brief Checks for issues with the input file, that may hinder encryption/decryption.
/// \param inFile the input file, to be encrypted/decrypted.
/// \param mode the mode of operation: encryption or decryption.
/// \throws std::invalid_argument if \p mode is invalid.
/// \throws std::runtime_error if the input file does not exist, is a directory,
/// is not a regular file, or is not readable.
void checkInputFile(const fs::path &inFile, const OperationMode &mode) {
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
            std::print("{} is not a regular file.\nDo you want to continue? (y/n): ", inFile.string());
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
bool createPath(const fs::path &filePath) noexcept {
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
            printColoredError('b', "{}", canonical(outFile).string());
            printColoredError('r', " already exists.\nDo you want to overwrite it? (y/n): ");
            if (!validateYesNo())
                throw std::runtime_error("Operation aborted.");

            // Determine if the output file can be written if it exists
            if (auto file = weakly_canonical(outFile).string(); !(isWritable(file) && isReadable(file)))
                throw std::runtime_error(std::format("{} is not writable/readable.", file));
        }
    }

    // Check if the input and output files are the same
    if (std::error_code ec; exists(outFile, ec) && equivalent(inFile, outFile))
        throw std::runtime_error("The input and the output file both refer to the same object.");

    // Check if there is enough space on the disk to save the output file.
    const auto availableSpace = getAvailableSpace(weakly_canonical(outFile));
    if (const auto fileSize = file_size(inFile); std::cmp_less(availableSpace, fileSize)) {
        printColoredError('r', "Not enough space to save ");
        printColoredError('c', "{}", weakly_canonical(outFile).string());

        printColoredError('y', "Required:  ");
        printColoredError('g', "{}", formatFileSize(fileSize));

        printColoredError('y', "Available: ");
        printColoredErrorln('r', "{}", formatFileSize(availableSpace));

        printColoredOutput('b', "\nDo you still want to continue? (y/n):");
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
        printColoredErrorln('r', "Invalid mode of operation.");
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
        printColoredOutput('g', "{}cryption completed successfully.\n{}crypted file saved as ", pre, pre);
        printColoredOutputln('b', "{}", outputFileName);

        // Preserve file permissions
        if (!copyFilePermissions(inputFileName, outputFileName))
            [[unlikely]]
                    printColoredOutputln('m', "Check the permissions of the {}crypted file.", pre);

        // Try to preserve the time of last modification
        copyLastWrite(inputFileName, outputFileName);
    } catch (const std::exception &ex) {
        printColoredErrorln('r', "Error: {}", ex.what());
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
        std::print("-------------");
        printColoredOutput('c', " file encryption/decryption utility ");
        std::println("-------------");
        printColoredOutputln('g', "1. Encrypt a file");
        printColoredOutputln('m', "2. Decrypt a file");
        printColoredOutputln('r', "3. Exit");
        std::println("--------------------------------------------------------------");

        if (const int choice = getResponseInt("Enter your choice: "); choice == 1 || choice == 2) {
            try {
                std::string pre = choice == 1 ? "En" : "De"; // the prefix string
                std::string pre_l{pre}; // the prefix in lowercase

                // Transform the prefix to lowercase
                std::ranges::transform(pre_l.begin(), pre_l.end(), pre_l.begin(),
                                       [](const unsigned char c) -> unsigned char {
                                           return std::tolower(c);
                                       });

                printColoredOutputln('c', "Enter the path to the file to {}crypt:", pre_l);
                std::string inputFile = getResponseStr();

                // Remove the trailing directory separator
                // ('\\' is considered as well in case the program is to be extended to Windows)
                if ((inputFile.ends_with('/') || inputFile.ends_with('\\')) && inputFile.size() > 1)
                    inputFile.erase(inputFile.size() - 1);

                fs::path inputPath(inputFile);
                if (!inputPath.is_absolute()) // The path should be absolute
                    inputPath = fs::current_path() / inputPath;
                checkInputFile(inputPath, static_cast<OperationMode>(choice));

                printColoredOutputln('c', "Enter the path to save the {}crypted file"
                                     "\n(or leave it blank to save it in the same directory):", pre_l);

                fs::path outputPath{getResponseStr()};
                if (!outputPath.is_absolute()) // If the path is not absolute
                    outputPath = fs::current_path() / outputPath;
                checkOutputFile(inputPath, outputPath, static_cast<OperationMode>(choice));

                std::println("Choose a cipher (All are 256-bit):");
                printColoredOutputln('b', "1. Advanced Encryption Standard (AES)");
                printColoredOutputln('c', "2. Camellia");
                printColoredOutputln('g', "3. Aria");
                printColoredOutputln('y', "4. Serpent");
                printColoredOutputln('m', "5. Twofish");

                std::println("Leave blank to use the default (AES)");

                int algo = getResponseInt();
                if (algo < 0 || algo > 5) {
                    // 0 is default (AES)
                    printColoredErrorln('r', "Invalid choice!");
                    continue;
                }
                const auto it = algoChoice.find(algo);
                auto cipher = it != algoChoice.end() ? it->second : Algorithms::AES;

                privacy::string password{getSensitiveInfo("Enter the password: ")};

                // Confirm the password before encryption
                if (choice == 1) {
                    int tries{0};
                    while (password.empty() && ++tries < 3) {
                        printColoredErrorln('r', "Please avoid empty or weak passwords. Please try again.");
                        password = getSensitiveInfo("Enter the password: ");
                    }
                    if (tries >= 3)
                        throw std::runtime_error("Empty encryption password.");

                    if (const privacy::string password2{getSensitiveInfo("Enter the password again: ")};
                        !verifyPassword(password2, hashPassword(password, crypto_pwhash_OPSLIMIT_INTERACTIVE,
                                                                crypto_pwhash_MEMLIMIT_INTERACTIVE))) {
                        printColoredErrorln('r', "Passwords do not match.");
                        continue;
                    }
                }
                printColoredOutput('g', "{}crypting ", pre);
                printColoredOutput('g', "{}", canonical(inputPath).string());
                printColoredOutput('g', " with ");
                printColoredOutput('c', "{}", algoDescription.find(cipher)->second);
                printColoredOutputln('g', "...");

                fileEncryptionDecryption(canonical(inputPath).string(), weakly_canonical(outputPath).string(),
                                         password, cipher, static_cast<OperationMode>(choice));
                std::println("");
            } catch (const std::exception &ex) {
                printColoredError('y', "Error: ");
                printColoredErrorln('r', "{}", ex.what());
                std::println("");
            }
        } else if (choice == 3) break;
        else printColoredErrorln('r', "Invalid choice!");
    }
}
