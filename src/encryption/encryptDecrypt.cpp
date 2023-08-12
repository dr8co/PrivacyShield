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
 * @brief A concept describing a type convertible & comparable to uintmax_t.
 * @tparam T - An integral type.
 */
concept Num = std::is_integral_v<T> && std::convertible_to<T, std::uintmax_t>;

/**
 * @brief A class to make file sizes more readable.
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

// A function to perform the necessary checks before encrypting/decrypting a file
inline void checkFiles(const fs::path &inFile, fs::path &outFile, const int &mode) {
    // Just to be sure
    if (mode != static_cast<int>(OperationMode::Encryption) && mode != static_cast<int>(OperationMode::Decryption))
        throw std::invalid_argument("Invalid mode of operation.");
    /** Check the input file **/

    // Ensure the input file exists and is not a directory
    if (!fs::exists(inFile))
        throw std::runtime_error(std::format("'{}' does not exist.", inFile.string()));
    if (fs::is_directory(inFile))
        throw std::runtime_error(std::format("'{}' is a directory.", inFile.string()));

    // Check if the input file is a regular file and ask for confirmation if it is not
    if (!fs::is_regular_file(inFile)) {
        if (mode == static_cast<int>(OperationMode::Encryption)) { // Encryption
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

    // Determine if the output file is a directory, and give it an appropriate name if so
    if (fs::is_directory(outFile)) {
        if (mode == static_cast<int>(OperationMode::Encryption)) {
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
        // If the output file is not specified, name it appropriately
    else if (outFile.string().empty()) {
        outFile = inFile;
        if (inFile.extension() == ".enc")
            outFile.replace_extension("");
        else if (mode == static_cast<int>(OperationMode::Encryption))
            outFile += ".enc";
        else if (mode == static_cast<int>(OperationMode::Decryption)) {
            outFile.replace_extension("");
            outFile += "_decrypted";
            outFile += inFile.extension();
        }
    }

    // Determine if the output file can be written/created
    if (auto file = outFile.string(); !(isWritable(file) && isReadable(file)))
        throw std::runtime_error(std::format("{} is not writable/readable.", file));

    // Check if there is enough space on the disk to save the output file.
    const auto availableSpace = getAvailableSpace(outFile.string());
    const auto fileSize = fs::file_size(inFile);
    if (std::cmp_less(availableSpace, fileSize)) {
        std::cerr << "Not enough space on disk to save " << outFile.string() << std::endl;
        std::cerr << "Required:  " << FormatFileSize(fileSize) << std::endl;
        std::cerr << "Available: " << FormatFileSize(availableSpace) << std::endl;

        std::cout << "Do you want to continue? (y/n) ";
        char ans;
        std::cin >> ans;
        std::cin.ignore();

        if (ans != 'y' && ans != 'Y')
            throw std::runtime_error("Insufficient storage space.");
    }
}

void fileEncryptionDecryption(const std::string &inputFileName, const std::string &outputFileName,
                              const std::string &password, unsigned int algo, int mode) {
    // Mode must be valid: either encryption or decryption
    if (mode != static_cast<int>(OperationMode::Encryption) && mode != static_cast<int>(OperationMode::Decryption)) {
        std::cout << "Invalid mode of operation." << std::endl;
        return;
    }

    try {
        const auto inputFilePath = fs::path(inputFileName);
        auto outputFilePath = fs::path(outputFileName);

        // Check the files
        checkFiles(inputFilePath, outputFilePath, mode);

        auto encryptDecrypt = [&](const std::string &algorithm) -> void {
            if (mode == static_cast<int>(OperationMode::Encryption))  // Encryption
                encryptFile(inputFilePath.string(), outputFilePath.string(), password, algorithm);
            else   // Decryption
                decryptFile(inputFilePath.string(), outputFilePath.string(), password, algorithm);
        };

        auto encryptDecryptMoreRounds = [&](const gcry_cipher_algos &algo) -> void {
            if (mode == static_cast<int>(OperationMode::Encryption))  // Encryption
                encryptFileWithMoreRounds(inputFilePath.string(), outputFilePath.string(), password, algo);
            else   // Decryption
                decryptFileWithMoreRounds(inputFilePath.string(), outputFilePath.string(), password, algo);
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
        auto pre = mode == static_cast<int>(OperationMode::Encryption) ? "En" : "De";
        std::cout << std::format("{}cryption completed successfully. \n{}crypted file saved at '{}'.", pre, pre,
                                 outputFilePath.string()) << std::endl;

        // Copy permissions
        if (!copyFilePermissions(inputFilePath.string(), outputFilePath.string()))
            std::cerr << "Check the permissions of the " << pre << "crypted file." << std::endl;

    } catch (std::exception &ex) {
        std::cerr << "Error: " << ex.what() << std::endl;
    }
}

