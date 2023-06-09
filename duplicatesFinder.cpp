#include <iostream>
#include <fstream>
#include <string>
#include <unordered_map>
#include <vector>
#include <dirent.h>
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

/**
 * traverseDirectory - recursively traverses a directory and collects file information.
 * @param directoryPath the directory to process.
 * @param files a vector to store the information from the files found in the directory.
 */
void traverseDirectory(const std::string &directoryPath, std::vector<FileInfo> &files) {
    DIR *dir = opendir(directoryPath.c_str());
    if (!dir) {
        std::cerr << "Failed to open directory: " << directoryPath << std::endl;
        return;
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != nullptr) {
        std::string fileName = entry->d_name;
        std::string fullPath = directoryPath + "/" + fileName;

        if (entry->d_type == DT_DIR) {
            if (fileName != "." && fileName != "..") {
                traverseDirectory(fullPath, files);
            }
        } else {
            FileInfo fileInfo;
            fileInfo.path = fullPath;
            fileInfo.hash = "";  // Hash will be calculated later
            files.push_back(fileInfo);
        }
    }

    closedir(dir);
}


/**
 * calculateHashes - calculates hashes for a range of files.
 * @param files the files to process.
 * @param start the index where processing starts.
 * @param end the index where processing ends.
 */
void calculateHashes(std::vector<FileInfo> &files, size_t start, size_t end) {
    if (sodium_init() == -1) {
        std::cerr << "Failed to initialize libsodium" << std::endl;
        return;
    }

    for (size_t i = start; i < end; ++i) {
        FileInfo fileInfoCopy = files[i];
        fileInfoCopy.hash = calculateBlake2b(fileInfoCopy.path);

        // Assign the modified copy back to the original object in the vector
        files[i].hash = fileInfoCopy.hash;
    }
}
