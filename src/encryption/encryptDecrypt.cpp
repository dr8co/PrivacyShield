// Privacy Shield: A Suite of Tools Designed to Facilitate Privacy Management.
// Copyright (C) 2023  Ian Duncan <dr8co@duck.com>
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

#include <algorithm>
#include <system_error>
#include <filesystem>
#include "encryptDecrypt.hpp"
#include "../utils/utils.hpp"
#include "../passwordManager/passwords.hpp"
#include <utility>
#include <iostream>
#include <format>
#include <cmath>
#include <unordered_map>

template<typename T>
/**
 * @brief A concept describing a type convertible & comparable with uintmax_t.
 * @tparam T - An integral type.
 */
concept Num = std::integral<T> && std::convertible_to<T, std::uintmax_t> &&
              std::equality_comparable_with<T, std::uintmax_t>;

/**
 * @brief A class to make file sizes more readable.
 * @details Adapted from https://en.cppreference.com/w/cpp/filesystem/file_size
 */
class FormatFileSize {
public:
    explicit FormatFileSize(const Num auto &size) {
        // Default negative values to zero
        if (std::cmp_greater(size, this->size))
            this->size = static_cast<std::uintmax_t>(size);
    }

private:
    std::uintmax_t size{0};

    friend
    std::ostream &operator<<(std::ostream &os, FormatFileSize ffs) {
        int i{};
        auto mantissa = static_cast<double>(ffs.size);
        for (; mantissa >= 1024.; mantissa /= 1024., ++i) {}
        mantissa = std::ceil(mantissa * 10.) / 10.;
        os << mantissa << "BKMGTPE"[i];
        return i == 0 ? os : os << "B (" << ffs.size << ')';
    }
};

/**
 * @brief Available encryption/decryption ciphers.
 */
enum class Algorithms : const
unsigned int {
        AES      = 1 << 0,
        Camellia = 1 << 1,
        Aria     = 1 << 2,
        Serpent  = 1 << 3,
        Twofish  = 1 << 4
};

/**
 * @brief Operation modes: encryption or decryption.
 */
enum class OperationMode : const
int {
        Encryption = 1,
        Decryption = 2
};

/**
 * @brief A structure to aid algorithm selection.
 */
const struct {
    const std::string AES      = "AES-256-CBC";
    const std::string Camellia = "CAMELLIA-256-CBC";
    const std::string Aria     = "ARIA-256-CBC";
    const gcry_cipher_algos Serpent = GCRY_CIPHER_SERPENT256;
    const gcry_cipher_algos Twofish = GCRY_CIPHER_TWOFISH;
} AlgoSelection;

namespace fs = std::filesystem;

inline void checkInputFile(fs::path &inFile, const OperationMode &mode) {
    if (mode != OperationMode::Encryption && mode != OperationMode::Decryption)
        throw std::invalid_argument("Invalid mode of operation.");

    // Ensure the input file exists and is not a directory
    if (!fs::exists(inFile))
        throw std::runtime_error(std::format("'{}' does not exist.", inFile.string()));
    if (fs::is_directory(inFile))
        throw std::runtime_error(std::format("'{}' is a directory.", inFile.string()));

    // Check if the input file is a regular file and ask for confirmation if it is not
    if (!fs::is_regular_file(inFile)) {
        if (mode == OperationMode::Encryption) { // Encryption
            std::cout << inFile.string() << " is not a regular file. \nDo you want to continue? (y/n): ";
            if (!validateYesNo())
                throw std::runtime_error(std::format("{} is not a regular file.", inFile.string()));
        } else
            throw std::runtime_error(
                    std::format("{} is not a regular file.", inFile.string())); // Encrypted files are regular
    }
    // Check if the input file is readable
    if (auto file = inFile.string();!isReadable(file))
        throw std::runtime_error(std::format("{} is not readable.", file));
}


inline void checkOutputFile(const fs::path &inFile, fs::path &outFile, const OperationMode &mode) {
    if (mode != OperationMode::Encryption && mode != OperationMode::Decryption)
        throw std::invalid_argument("Invalid mode of operation.");

    // Determine if the output file is a directory, and give it an appropriate name if so
    if (fs::is_directory(outFile)) {
        if (mode == OperationMode::Encryption) {
            outFile /= inFile.filename();
            outFile += ".enc";
        } else if (inFile.extension() == ".enc") // Decryption: strip the '.enc' extension
            outFile /= inFile.stem();
        else outFile /= inFile.filename();
    }

    // If the output file is not specified, name it appropriately
    if (outFile.string().empty()) {
        outFile = inFile;
        if (inFile.extension() == ".enc")
            outFile.replace_extension("");
        else if (mode == OperationMode::Encryption)
            outFile += ".enc";
        else if (mode == OperationMode::Decryption) {
            outFile.replace_extension("");
            outFile += "_decrypted";
            outFile += inFile.extension();
        }
    }

    // If the output file exists, ask for confirmation for overwriting
    if (auto file = outFile.string();fs::exists(outFile)) {
        std::cout << file << " already exists. \nDo you want to overwrite it? (y/n): ";
        if (!validateYesNo())
            throw std::runtime_error("Operation aborted.");
    }

    // Determine if the output file can be written if it exists
    if (auto file = outFile.string(); fs::exists(outFile) && !(isWritable(file) && isReadable(file)))
        throw std::runtime_error(std::format("{} is not writable/readable.", file));

    // Check if there is enough space on the disk to save the output file.
    const auto availableSpace = getAvailableSpace(outFile.string());
    const auto fileSize = fs::file_size(inFile);
    if (std::cmp_less(availableSpace, fileSize)) {
        std::cerr << "Not enough space on disk to save " << outFile.string() << std::endl;
        std::cerr << "Required:  " << FormatFileSize(fileSize) << std::endl;
        std::cerr << "Available: " << FormatFileSize(availableSpace) << std::endl;

        std::cout << "\nDo you want to continue? (y/n) ";
        if (!validateYesNo())
            throw std::runtime_error("Insufficient storage space.");
    }
}

inline void copyLastWrite(const std::string &srcFile, const std::string &destFile) noexcept {
    std::error_code ec;
    auto srcTime = fs::last_write_time(srcFile, ec);
    if (ec) ec.clear();
    fs::last_write_time(destFile, srcTime, ec);
}

void fileEncryptionDecryption(const std::string &inputFileName, const std::string &outputFileName,
                              const privacy::string &password, unsigned int algo, OperationMode mode) {
    // The mode must be valid: must be either encryption or decryption
    if (mode != OperationMode::Encryption && mode != OperationMode::Decryption) {
        std::cout << "Invalid mode of operation." << std::endl;
        return;
    }

    try {
        /** Encrypts/decrypts a file based on the passed mode and algorithm. */
        auto encryptDecrypt = [&](const std::string &algorithm) -> void {
            if (mode == OperationMode::Encryption) // Encryption
                encryptFile(inputFileName, outputFileName, password, algorithm);
            else   // Decryption
                decryptFile(inputFileName, outputFileName, password, algorithm);
        };

        /** Encrypts/decrypts a file using a cipher with more rounds. */
        auto encryptDecryptMoreRounds = [&](const gcry_cipher_algos &algo) -> void {
            if (mode == OperationMode::Encryption)  // Encryption
                encryptFileWithMoreRounds(inputFileName, outputFileName, password, algo);
            else   // Decryption
                decryptFileWithMoreRounds(inputFileName, outputFileName, password, algo);
        };

        // Encrypt/decrypt with the specified algorithm
        if (algo & static_cast<unsigned int>(Algorithms::AES))
            encryptDecrypt(AlgoSelection.AES);
        else if (algo & static_cast<unsigned int>(Algorithms::Camellia))
            encryptDecrypt(AlgoSelection.Camellia);
        else if (algo & static_cast<unsigned int>(Algorithms::Aria))
            encryptDecrypt(AlgoSelection.Aria);
        else if (algo & static_cast<unsigned int>(Algorithms::Serpent))
            encryptDecryptMoreRounds(AlgoSelection.Serpent);
        else if (algo & static_cast<unsigned int>(Algorithms::Twofish))
            encryptDecryptMoreRounds(AlgoSelection.Twofish);

        // If we reach here, the operation was successful
        auto pre = mode == OperationMode::Encryption ? "En" : "De";
        std::cout << std::format("{}cryption completed successfully. \n{}crypted file saved at '{}'", pre, pre,
                                 outputFileName) << std::endl;

        // Preserve file permissions
        if (!copyFilePermissions(inputFileName, outputFileName))
            std::cerr << "Check the permissions of the " << pre << "crypted file." << std::endl;

        // Try to preserve the time of last modification
        copyLastWrite(inputFileName, outputFileName);

    } catch (std::exception &ex) {
        std::cerr << "Error: " << ex.what() << std::endl;
    }
}

void encryptDecrypt() {
    // I'm avoiding writing many if-else statements with these hashmaps
    std::unordered_map<int, Algorithms> algoChoice = {
            {0, Algorithms::AES}, // Default
            {1, Algorithms::AES},
            {2, Algorithms::Camellia},
            {3, Algorithms::Aria},
            {4, Algorithms::Serpent},
            {5, Algorithms::Twofish}
    };

    std::unordered_map<Algorithms, std::string> algoDescription = {
            {Algorithms::AES,      "256-bit AES in CBC mode"},
            {Algorithms::Camellia, "256-bit Camellia in CBC mode"},
            {Algorithms::Aria,     "256-bit Aria in CBC mode"},
            {Algorithms::Serpent,  "256-bit Serpent in CTR mode"},
            {Algorithms::Twofish,  "256-bit Twofish in CTR mode"}
    };

    while (true) {
        std::cout << "------------- file encryption/decryption utility -------------" << std::endl;
        std::cout << "1. Encrypt a file" << std::endl;
        std::cout << "2. Decrypt a file" << std::endl;
        std::cout << "3. Exit" << std::endl;
        std::cout << "--------------------------------------------------------------" << std::endl;

        int choice = getResponseInt("Enter your choice: ");

        if (choice == 1 || choice == 2) {
            try {
                std::string pre = choice == 1 ? "En" : "De";
                std::string pre_l{pre};

                std::ranges::transform(pre_l.begin(), pre_l.end(), pre_l.begin(), [](unsigned char c) -> unsigned char {
                    return std::tolower(c);
                });
                std::cout << "Enter the path to the file to " << pre_l << "crypt:" << std::endl;
                std::string inputFile = getResponseStr();

                // Remove the trailing directory separator
                // ('\\' is considered as well in case the program is to be extended to Windows)
                if ((inputFile.ends_with('/') || inputFile.ends_with('\\')) && inputFile.size() > 1)
                    inputFile.erase(inputFile.size() - 1);

                fs::path inputPath(inputFile);
                checkInputFile(inputPath, static_cast<OperationMode>(choice));

                std::cout << "Enter the path to save the " << pre_l
                          << "crypted file \n(or leave it blank to save it in the same directory): " << std::endl;
                std::string outputFile = getResponseStr();

                if ((outputFile.ends_with('/') || outputFile.ends_with('\\')) && outputFile.size() > 1)
                    outputFile.erase(outputFile.size() - 1);

                fs::path outputPath(outputFile);
                checkOutputFile(inputPath, outputPath, static_cast<OperationMode>(choice));

                std::cout << "Choose a cipher (All are 256-bit): " << std::endl;
                std::cout << "1. Advanced Encryption Standard (AES)" << std::endl;
                std::cout << "2. Camellia" << std::endl;
                std::cout << "3. Aria" << std::endl;
                std::cout << "4. Serpent" << std::endl;
                std::cout << "5. Twofish" << std::endl;
                std::cout << "Leave blank to use the default (AES)" << std::endl;

                int algo = getResponseInt();
                if (algo < 0 || algo > 5) { // 0 is default (AES)
                    std::cout << "Invalid choice!" << std::endl;
                    continue;
                }

                auto it = algoChoice.find(algo);
                auto cipher = it != algoChoice.end() ? it->second : Algorithms::AES;

                privacy::string password{getSensitiveInfo("Enter the password: ")};

                // Confirm the password during encryption
                if (choice == 1) {
                    privacy::string password2{getSensitiveInfo("Enter the password again: ")};

                    if (!verifyPassword(password2, hashPassword(password, crypto_pwhash_OPSLIMIT_INTERACTIVE,
                                                                crypto_pwhash_MEMLIMIT_INTERACTIVE))) {
                        std::cerr << "Passwords do not match." << std::endl;
                        continue;
                    }
                }

                std::cout << pre << "crypting " << inputPath << " with " << algoDescription.find(cipher)->second
                          << "..." << std::endl;

                fileEncryptionDecryption(inputPath.string(), outputPath.string(), password,
                                         static_cast<int>(cipher), static_cast<OperationMode>(choice));
                std::cout << std::endl;

            } catch (std::exception &ex) {
                std::cerr << "Error: " << ex.what() << std::endl;
                std::cout << std::endl;
                continue;
            }

        } else if (choice == 3) break;
        else std::cerr << "Invalid choice!" << std::endl;
    }
}

