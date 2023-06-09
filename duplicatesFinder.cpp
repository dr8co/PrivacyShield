#include <iostream>
#include <fstream>
#include <string>
#include <sodium.h>
#include <thread>

// Structure to store file information.
struct FileInfo {
    std::string path; // path to the file.
    std::string hash; // Blake2b hash of the file.
};

/**
 * calculateBlake2b - Calculates the Blake2b hash of a file.
 * @param filePath path to the file.
 * @return a string of the hash of the file.
 */
std::string calculateBlake2b(const std::string &filePath) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file) {
        std::cerr << "Failed to open file: " << filePath << std::endl;
        return "";
    }

    const size_t bufferSize = 4096;
    char buffer[bufferSize];

    crypto_generichash_blake2b_state state;
    crypto_generichash_blake2b_init(&state, nullptr, 0, crypto_generichash_blake2b_BYTES);

    while (file.read(buffer, bufferSize)) {
        crypto_generichash_blake2b_update(&state, reinterpret_cast<const unsigned char *>(buffer), bufferSize);
    }

    int remainingBytes = file.gcount();
    crypto_generichash_blake2b_update(&state, reinterpret_cast<const unsigned char *>(buffer), remainingBytes);

    unsigned char hash[crypto_generichash_blake2b_BYTES];
    crypto_generichash_blake2b_final(&state, hash, crypto_generichash_blake2b_BYTES);

    std::string blake2bHash(reinterpret_cast<const char *>(hash), crypto_generichash_blake2b_BYTES);

    file.close();
    return blake2bHash;
}
