#include <iostream>
#include <fstream>
#include <string>
#include <unordered_map>
#include <vector>
#include <filesystem>
#include <sodium.h>
#include <thread>

namespace fs = std::filesystem;

// Structure to store file information.
struct FileInfo {
    std::string path; // path to the file.
    std::string hash; // Blake2b hash of the file.
};

/**
 * @brief Calculates the Blake2b hash of a file.
 * @param filePath path to the file.
 * @return a string of the hash of the file.
 */
std::string calculateBlake2b(const std::string &filePath) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file)
        throw std::runtime_error("Failed to open file: " + filePath);

    const size_t bufferSize = 4096;
    std::vector<char> buffer(bufferSize);

    crypto_generichash_blake2b_state state;
    crypto_generichash_blake2b_init(&state, nullptr, 0, crypto_generichash_blake2b_BYTES);

    while (file.read(buffer.data(), bufferSize)) {
        crypto_generichash_blake2b_update(&state, reinterpret_cast<const unsigned char *>(buffer.data()), bufferSize);
    }

    size_t remainingBytes = file.gcount();
    crypto_generichash_blake2b_update(&state, reinterpret_cast<const unsigned char *>(buffer.data()), remainingBytes);

    unsigned char hash[crypto_generichash_blake2b_BYTES];
    crypto_generichash_blake2b_final(&state, hash, crypto_generichash_blake2b_BYTES);

    std::string blake2bHash(reinterpret_cast<const char *>(hash), crypto_generichash_blake2b_BYTES);

    file.close();
    return blake2bHash;
}

/**
 * @brief recursively traverses a directory and collects file information.
 * @param directoryPath the directory to process.
 * @param files a vector to store the information from the files found in the directory.
 */
void traverseDirectory(const std::string &directoryPath, std::vector<FileInfo> &files) {
    for (const auto &entry: fs::recursive_directory_iterator(directoryPath)) {
        if (entry.is_regular_file()) {
            FileInfo fileInfo;
            fileInfo.path = entry.path().string();
            fileInfo.hash = "";  // Hash will be calculated later
            files.push_back(fileInfo);
        } else if (!entry.is_directory())
            std::cout << "Not processing: " << entry << ". Not a regular file." << std::endl;
    }
}


/**
 * @brief calculates hashes for a range of files.
 * @param files the files to process.
 * @param start the index where processing starts.
 * @param end the index where processing ends.
 */
void calculateHashes(std::vector<FileInfo> &files, size_t start, size_t end) {
    if (start > end || end > files.size())
        throw std::runtime_error("Invalid range");

    for (size_t i = start; i < end; ++i) {
        files[i].hash = calculateBlake2b(files[i].path);
    }
}

/**
 * @brief finds duplicate files (by content) in a directory.
 * @param directoryPath - the directory to process.
 * @return True if duplicates are found, else False.
 */
std::pair<bool, size_t> findDuplicates(const std::string &directoryPath) {
    std::pair<bool, size_t> ret{false, 0};
    if (sodium_init() == -1) {
        throw std::runtime_error("Failed to initialize libsodium");
    }

    // Collect file information
    std::vector<FileInfo> files;
    traverseDirectory(directoryPath, files);

    // Number of threads to use (Simple C11 threads for now)
    const unsigned int numThreads = std::thread::hardware_concurrency();

    // Divide files among threads and calculate hashes in parallel
    std::vector<std::thread> threads;
    size_t filesProcessed = files.size();
    size_t filesPerThread = filesProcessed / numThreads;
    size_t start = 0;

    for (int i = 0; i < numThreads - 1; ++i) {
        threads.emplace_back(calculateHashes, std::ref(files), start, start + filesPerThread);
        start += filesPerThread;
    }

    // The last thread may handle slightly more files to account for division remainder
    threads.emplace_back(calculateHashes, std::ref(files), start, files.size());

    // Wait for all threads to finish
    for (auto &thread: threads) {
        thread.join();
    }

    // Map to store hashes and corresponding file paths
    std::unordered_map<std::string, std::vector<std::string>> hashMap;

    // Iterate over files and identify duplicates
    for (const auto &fileInfo: files) {
        const std::string &hash = fileInfo.hash;
        const std::string &filePath = fileInfo.path;

        hashMap[hash].push_back(filePath);
    }

    size_t duplicatesSet = 0, duplicateFiles = 0;

    // Display duplicate files
    std::cout << "Duplicates found:" << std::endl;
    for (const auto &pair: hashMap) {
        const std::vector<std::string> &duplicates = pair.second;

        if (duplicates.size() > 1) {
            ret.first = true;
            ++duplicatesSet;

            std::cout << "Duplicate files set " << duplicatesSet << ":" << std::endl;
            for (const std::string &filePath: duplicates) {
                std::cout << "  " << filePath << std::endl;
                ++duplicateFiles;
            }
        }
    }
    std::cout << "\nFiles processed: " << filesProcessed << std::endl;
    ret.second = duplicateFiles;

    return ret;
}
