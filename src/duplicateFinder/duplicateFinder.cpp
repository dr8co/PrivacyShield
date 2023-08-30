#include <iostream>
#include <fstream>
#include <system_error>
#include <thread>
#include <vector>
#include <unordered_map>
#include <filesystem>
#include <sodium.h>
#include <blake3.h>
#include <format>
#include "../utils/utils.hpp"
#include "duplicateFinder.hpp"

namespace fs = std::filesystem;

constexpr std::size_t CHUNK_SIZE = 4096;  // Read and process files in chunks of 4 kB


/**
 * @brief Represents a file by its path (canonical) and hash.
 */
struct FileInfo {
    std::string path; // path to the file.
    std::string hash; // Blake2b hash of the file.
};


/**
 * @brief Calculates the 256-bit BLAKE3 hash of a file.
 *
 * @param filePath path to the file.
 * @return Base64-encoded hash of the file.
 */
std::string calculateBlake3(const std::string &filePath) {
    // Open the file
    std::ifstream file(filePath, std::ios::binary);
    if (!file)
        throw std::runtime_error(std::format("Failed to open '{}' for hashing.", filePath));

    // Initialize the BLAKE3 hasher
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);

    // Update the hasher with the file contents in chunks of 4 kB
    std::vector<char> buffer(CHUNK_SIZE);
    while (file.read(buffer.data(), CHUNK_SIZE))
        blake3_hasher_update(&hasher, buffer.data(), CHUNK_SIZE);

    // Update the hasher with the last chunk of data
    std::size_t remainingBytes = file.gcount();
    blake3_hasher_update(&hasher, buffer.data(), remainingBytes);

    // Finalize the hash calculation
    std::vector<unsigned char> digest(BLAKE3_OUT_LEN);
    blake3_hasher_finalize(&hasher, digest.data(), BLAKE3_OUT_LEN);

    return base64Encode(digest);
}

/**
 * @brief handles file i/o errors during low-level file operations.
 * @param filename path to the file on which an error occurred.
 */
inline void handleAccessError(const std::string &filename) {
    std::string errMsg;
    switch (errno) {
        case EACCES:        // Permission denied
            errMsg = "You do not have permission to access this item";
            break;
        case EEXIST:        // File exists
            errMsg = "already exists";
            break;
        case EISDIR:        // Is a directory
            errMsg = "is a directory";
            break;
        case ELOOP:         // Too many symbolic links encountered
            errMsg = "is a loop";
            break;
        case ENAMETOOLONG:  // The filename is too long
            errMsg = "the path is too long";
            break;
        case ENOENT:        // No such file or directory
            errMsg = "path does not exist";
            break;
        case EROFS:         // Read-only file system
            errMsg = "the file system is read-only";
            break;
        default:            // Success (most likely)
            return;
    }

    printColor(std::format("Skipping '{}': {}.", filename, errMsg), 'r', true, std::cerr);
}

/**
 * @brief recursively traverses a directory and collects file information.
 * @param directoryPath the directory to process.
 * @param files a vector to store the information from the files found in the directory.
 */
void traverseDirectory(const std::string &directoryPath, std::vector<FileInfo> &files) {

    for (const auto &entry: fs::recursive_directory_iterator(directoryPath,
                                                             fs::directory_options::skip_permission_denied)) {
        if (entry.exists()) { // skip broken symlinks
            // Make sure we can read the entry
            if (isReadable(entry.path())) [[likely]] {

                // process only regular files
                if (entry.is_regular_file()) [[likely]] {
                    FileInfo fileInfo;

                    // Update the file details
                    fileInfo.path = entry.path().string();
                    fileInfo.hash = "";  // the hash will be calculated later
                    files.emplace_back(fileInfo);

                } else if (!entry.is_directory()) // Neither regular nor a directory
                    std::cerr << std::format("Skipping '{}': Not a regular file.", entry.path().string()) << std::endl;

            } else handleAccessError(entry.path().string());
        }
    }
}

/**
 * @brief calculates hashes for a range of files.
 * @param files the files to process.
 * @param start the index where processing starts.
 * @param end the index where processing ends.
 */
void calculateHashes(std::vector<FileInfo> &files, std::size_t start, std::size_t end) {
    // Check if the range is valid
    if (start > end || end > files.size())
        throw std::range_error("Invalid range.");

    // Calculate hashes for the files in the range
    for (std::size_t i = start; i < end; ++i)
        files[i].hash = calculateBlake3(files[i].path);
}

/**
 * @brief finds duplicate files (by content) in a directory.
 * @param directoryPath - the directory to process.
 * @return True if duplicates are found, else False.
 */
std::size_t findDuplicates(const std::string &directoryPath) {
    // Initialize libsodium if not already initialized
    if (sodium_init() == -1)
        throw std::runtime_error("Failed to initialize libsodium.");

    // Collect file information
    std::vector<FileInfo> files;
    traverseDirectory(directoryPath, files);
    std::size_t filesProcessed = files.size();
    if (filesProcessed < 1) return 0;

    // Number of threads to use
    unsigned int n{std::jthread::hardware_concurrency()};
    const unsigned int numThreads{n ? n : 8}; // Use 8 threads if hardware_concurrency() fails

    // Divide files among threads
    std::vector<std::jthread> threads;
    std::size_t filesPerThread = filesProcessed / numThreads;
    std::size_t start = 0;

    // Calculate the hashes in parallel
    for (int i = 0; i < static_cast<int>(numThreads - 1); ++i) {
        threads.emplace_back(calculateHashes, std::ref(files), start, start + filesPerThread);
        start += filesPerThread;
    }
    // The last thread may handle slightly more files to account for the division remainder
    threads.emplace_back(calculateHashes, std::ref(files), start, files.size());

    // Wait for all threads to finish execution
    for (auto &thread: threads) {
        thread.join();
    }
    // A hash map to map the files to their corresponding hashes
    std::unordered_map<std::string, std::vector<std::string>> hashMap;

    // Iterate over files and identify duplicates
    for (const auto &fileInfo: files) {
        const std::string &hash = fileInfo.hash;
        const std::string &filePath = fileInfo.path;

        hashMap[hash].push_back(filePath);
    }

    std::size_t duplicatesSet{0}, numDuplicates{0};

    // Display duplicate files
    std::cout << "Duplicates found:" << std::endl;
    for (const auto &pair: hashMap) {
        const std::vector<std::string> &duplicates = pair.second;

        if (duplicates.size() > 1) {
            ++duplicatesSet;

            // Show the duplicates in their sets
            printColor("Duplicate files set ", 'c');
            printColor(duplicatesSet, 'g');
            printColor(":", 'c', true);
            for (const std::string &filePath: duplicates) {
                std::cout << "  " << filePath << std::endl;
                ++numDuplicates;
            }
        }
    }
    std::cout << "\nFiles processed: " << filesProcessed << std::endl;

    return numDuplicates;
}

/**
 * @brief A simple duplicate file detective.
 */
void duplicateFinder() {
    while (true) {
        std::cout << "\n------------------- Duplicate Finder -------------------\n";
        std::cout << "1. Scan for duplicate files\n2. Exit\n";
        std::cout << "--------------------------------------------------------" << std::endl;

        int resp = getResponseInt("Enter your choice:");

        if (resp == 1) {
            try {
                std::string dirPath = getResponseStr("Enter the path to the directory to scan: ");

                if (auto len = dirPath.size(); len > 1 && (dirPath.ends_with('/') || dirPath.ends_with('\\')))
                    dirPath.erase(len - 1);

                std::error_code ec;
                fs::file_status fileStatus = fs::status(dirPath, ec);
                if (ec) {
                    std::cerr << "Unable to determine " << dirPath << "'s status: " << ec.message() << std::endl;
                    ec.clear();
                    continue;
                }
                if (!fs::exists(fileStatus)) {
                    std::cerr << "'" << dirPath << "' does not exist." << std::endl;
                    continue;
                }
                if (!fs::is_directory(fileStatus)) {
                    std::cerr << "'" << dirPath << "' is not a directory." << std::endl;
                    continue;
                }

                if (fs::is_empty(dirPath, ec)) {
                    if (ec) ec.clear();
                    else {
                        std::cout << "The directory is empty." << std::endl;
                        continue;
                    }
                }

                std::cout << "Scanning " << dirPath << "..." << std::endl;
                std::size_t duplicateFiles = findDuplicates(dirPath);

                std::cout << "Duplicates "
                          << (duplicateFiles > 0 ? "found: " + std::to_string(duplicateFiles) : "not found.")
                          << std::endl;

            } catch (const std::exception &ex) {
                std::cerr << "An error occurred: " << ex.what() << std::endl;
                continue;
            }

        } else if (resp == 2) break;
        else {
            std::cerr << "Invalid option!" << std::endl;
            continue;
        }
    }

}