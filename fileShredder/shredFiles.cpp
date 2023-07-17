#include <iostream>
#include <fstream>
#include <random>
#include <filesystem>

namespace fs = std::filesystem;

/**
 * @brief overwrites a file with random bytes.
 * @param file output file stream object.
 * @param fileSize the size of the file in bytes.
 * @param nPasses the number of passes to overwrite the file.
 */
void overwriteRandom(std::ofstream &file, const size_t fileSize, int nPasses = 1) {

    // Create a random device for generating secure random numbers
    std::random_device rd;
    std::uniform_int_distribution<uint8_t> dist(0, 255);

    for (int i = 0; i < nPasses; ++i) {
        // (Re)seed the Mersenne Twister engine in every iteration
        std::mt19937_64 gen(rd());

        // Overwrite the file with random data
        for (size_t pos = 0; pos < fileSize; ++pos) {
            uint8_t randomByte = dist(gen);
            file.write(reinterpret_cast<char *>(&randomByte), sizeof(uint8_t));
        }
    }

}

/**
 * @brief overwrites a file wih a constant byte.
 * @tparam T type of the byte.
 * @param filename the path to the file to be overwritten.
 * @param byte the byte to overwrite the file with.
 * @param fileSize the size of the file in bytes.
 *
 */
template<typename T>
void overwriteConstantByte(std::ofstream &file, T byte, const size_t fileSize) {
    for (std::streamoff pos = 0; pos < fileSize; ++pos) {
        file.write(reinterpret_cast<char *>(&byte), sizeof(T));
    }

}

/**
 * @brief shreds a file by overwriting it with random bytes
 * @param filename path to the file being overwritten
 */
void simpleShred(const std::string &filename, const int &nPasses = 3) {
    std::ofstream file(filename, std::ios::binary | std::ios::in);
    if (!file)
        throw std::runtime_error("Failed to open file: " + filename);

    // Get the file size
    file.seekp(0, std::ios::end);
    std::streamoff fileSize = file.tellp();
    file.seekp(0, std::ios::beg);

    // Shred the file
    overwriteRandom(file, fileSize, nPasses);

    file.close();
    fs::remove(filename);
}

/**
 * @brief shreds a file using a simple version of
 * The U.S Department of Defence (DoD) 5220.22-M Standard algorithm.
 * @param filename - the path to the file to be shred.
 */
void dod5220Shred(const std::string &filename) {
    std::ofstream file(filename, std::ios::binary | std::ios::in);
    if (!file)
        throw std::runtime_error("Failed to open file: " + filename);

    // Get the file size
    file.seekp(0, std::ios::end);
    std::streamoff fileSize = file.tellp();
    file.seekp(0, std::ios::beg);

    // Pass 1: Overwrite with zeros
    uint8_t zeroByte = 0;
    overwriteConstantByte(file, zeroByte, fileSize);

    // Pass 2: Overwrite with ones
    uint8_t oneByte = 0xFF;
    overwriteConstantByte(file, oneByte, fileSize);

    // Pass 3: Overwrite with random data
    overwriteRandom(file, fileSize);

    file.close();
    fs::remove(filename);
}
