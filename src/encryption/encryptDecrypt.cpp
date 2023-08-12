#include <system_error>
#include <filesystem>
#include "encryptDecrypt.hpp"
#include "../utils/utils.hpp"
#include <utility>
#include <iostream>
#include <format>
#include <cmath>


template<typename T>
/**
 * @brief A concept describing a type convertible to uintmax_t.
 * @tparam T - An integral type.
 */
concept Num = std::is_integral_v<T> && std::convertible_to<T, std::uintmax_t>;

/**
 * @brief A class
 */
class FormatFileSize {
public:
    explicit FormatFileSize(const Num auto &size) {
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
 * @brief Available encryption/decryption ciphers
 */
enum class Algorithms : const
unsigned int {
AES = 1 << 0,
        Camellia = 1 << 1,
        Aria = 1 << 2,
        Serpent = 1 << 3,
        Twofish = 1 << 4
};

/**
 * @brief A structure to aid algorithm selection
 */
const struct {
    const std::string AES = "AES-256-CBC";
    const std::string Camellia = "CAMELLIA-256-CBC";
    const std::string Aria = "ARIA-256-CBC";
    const gcry_cipher_algos Serpent = GCRY_CIPHER_SERPENT256;
    const gcry_cipher_algos Twofish = GCRY_CIPHER_TWOFISH;
} AlgoSelection;

namespace fs = std::filesystem;

// A function to perform the necessary checks before encrypting/decrypting a file
inline void checkFiles(const fs::path &inFile, fs::path &outFile, const int &mode = 1) {
    if (mode != 1 && mode != 2)
        throw std::invalid_argument("Invalid mode of operation.");
    /** Check the input file **/

    // Determine if the input file exists and is not a directory
    if (!fs::exists(inFile))
        throw std::runtime_error(std::format("'{}' does not exist.", inFile.string()));
    if (fs::is_directory(inFile))
        throw std::runtime_error(std::format("'{}' is a directory.", inFile.string()));

    // Check if the input file is a regular file and ask for confirmation if it is not
    if (!fs::is_regular_file(inFile)) {
        if (mode == 1) { // Encryption
            std::cout << inFile.string() << " is not a regular file. \nDo you want to continue? (y/n): ";
            char answer;
            std::cin >> answer;
            std::cin.ignore();
            if (answer != 'y' && answer != 'Y')
                throw std::runtime_error(std::format("{} is not a regular file.", inFile.string()));
        } else
            throw std::runtime_error(
                    std::format("{} is not a regular file.", inFile.string())); // Encrypted files are regular
    }
    // Check if the input file is readable
    if (auto file = inFile.string();!isReadable(file))
        throw std::runtime_error(std::format("{} is not readable.", file));

    /** Check the output file **/

    // Determine if the output file is a directory, and if it is, append the input file name, input file extension, and ".enc" to it
    if (fs::is_directory(outFile)) {
        if (mode == 1) {
            outFile /= inFile.filename();
            outFile += ".enc";
        } else if (inFile.extension() == ".enc") // Decryption: strip the '.enc' extension
            outFile /= inFile.stem();
        else outFile /= inFile.filename();
    }

    // Determine if the output file exists ask for confirmation if it does
    if (auto file = outFile.string();fs::exists(outFile)) {
        std::cout << file << " already exists. \nDo you want to overwrite it? (y/n): ";
        char answer;
        std::cin >> answer;
        std::cin.ignore();
        if (answer != 'y' && answer != 'Y')
            throw std::runtime_error("Operation aborted.");
    }
        // Determine if the output file is empty, and use the input file name, input file extension, and ".enc" if it is
    else if (outFile.string().empty()) {
        outFile = inFile;
        if (inFile.extension() == ".enc")
            outFile.replace_extension("");
        else if (mode == 1)
            outFile += ".enc";
        else if (mode == 2) {
            outFile.replace_extension("");
            outFile += "_decrypted";
            outFile += inFile.extension();
        }
    }

    // Determine if the output file is writable
    if (auto file = outFile.string(); !(isWritable(file) && isReadable(file)))
        throw std::runtime_error(std::format("{} is not writable/readable.", file));

    // Determine if there is enough space on the disk to save the encrypted file.
    const auto availableSpace = getAvailableSpace(outFile.string());
    const auto fileSize = fs::file_size(inFile);
    if (std::cmp_less(availableSpace, fileSize)) {
        std::cout << "Not enough space on disk to save " << outFile.string() << std::endl;
        std::cout << "Required:  " << FormatFileSize(fileSize) << std::endl;
        std::cout << "Available: " << FormatFileSize(availableSpace) << std::endl;

        std::cout << "Do you want to continue? (y/n) ";
        char ans;
        std::cin >> ans;
        std::cin.ignore();

        if (ans != 'y' && ans != 'Y')
            throw std::runtime_error("Insufficient storage space.");
    }
}

void fileEncryption(const std::string &inputFileName, const std::string &outputFileName, const std::string &password,
                    unsigned int algo) {
    const auto inputFilePath = fs::path(inputFileName);
    auto outputFilePath = fs::path(outputFileName);
    int mode{1}; // Encryption mode

    // Check the file
    checkFiles(inputFilePath, outputFilePath, mode);

    if (algo & static_cast<unsigned int>(Algorithms::AES))
        encryptFile(inputFilePath.string(), outputFilePath.string(), password, AlgoSelection.AES);
    else if (algo & static_cast<unsigned int>(Algorithms::Camellia))
        encryptFile(inputFilePath.string(), outputFilePath.string(), password, AlgoSelection.Camellia);
    else if (algo & static_cast<unsigned int>(Algorithms::Aria))
        encryptFile(inputFilePath.string(), outputFilePath.string(), password, AlgoSelection.Aria);
    else if (algo & static_cast<unsigned int>(Algorithms::Serpent))
        encryptFileWithMoreRounds(inputFilePath.string(), outputFilePath.string(), password, AlgoSelection.Serpent);
    else if (algo & static_cast<unsigned int>(Algorithms::Twofish))
        encryptFileWithMoreRounds(inputFilePath.string(), outputFilePath.string(), password, AlgoSelection.Twofish);

}

void fileDecryption(const std::string &inputFileName, const std::string &outputFileName, const std::string &password,
                    unsigned int algo) {
    const auto inputFilePath = fs::path(inputFileName);
    auto outputFilePath = fs::path(outputFileName);
    int mode{2}; // Decryption mode

    // Check the file
    checkFiles(inputFilePath, outputFilePath, mode);

    // Decrypt the file
    if (algo & static_cast<unsigned int>(Algorithms::AES))
        decryptFile(inputFilePath.string(), outputFilePath.string(), password, AlgoSelection.AES);
    else if (algo & static_cast<unsigned int>(Algorithms::Camellia))
        decryptFile(inputFilePath.string(), outputFilePath.string(), password, AlgoSelection.Camellia);
    else if (algo & static_cast<unsigned int>(Algorithms::Aria))
        decryptFile(inputFilePath.string(), outputFilePath.string(), password, AlgoSelection.Aria);
    else if (algo & static_cast<unsigned int>(Algorithms::Serpent))
        decryptFileWithMoreRounds(inputFilePath.string(), outputFilePath.string(), password, AlgoSelection.Serpent);
    else if (algo & static_cast<unsigned int>(Algorithms::Twofish))
        decryptFileWithMoreRounds(inputFilePath.string(), outputFilePath.string(), password, AlgoSelection.Twofish);
}

