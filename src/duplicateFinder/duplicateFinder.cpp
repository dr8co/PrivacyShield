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

#include "../utils/utils.hpp"
#include "duplicateFinder.hpp"
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

namespace fs = std::filesystem;

constexpr std::size_t CHUNK_SIZE = 4096;  // Read and process files in chunks of 4 kB


/// \brief Represents a file by its path (canonical) and hash.
struct FileInfo {
    std::string path; // the path to the file.
    std::string hash; // the file's BLAKE3 hash
};

/// \brief Calculates the 256-bit BLAKE3 hash of a file.
/// \param filePath path to the file.
/// \return Base64-encoded hash of the file.
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

/// \brief handles file i/o errors during low-level file operations.
/// \param filename path to the file on which an error occurred.
inline void handleAccessError(const std::string &filename) {
    std::string errMsg;
    errMsg.reserve(50);

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

/// \brief recursively traverses a directory and collects file information.
/// \param directoryPath the directory to process.
/// \param files a vector to store the information from the files found in the directory.
void traverseDirectory(const std::string &directoryPath, std::vector<FileInfo> &files) {
    std::error_code ec;

    for (const auto &entry: fs::recursive_directory_iterator(directoryPath,
                                                             fs::directory_options::skip_permission_denied |
                                                             fs::directory_options::follow_directory_symlink)) {
        if (entry.exists(ec)) { // In case of broken symlinks
            if (ec) {
                printColor(std::format("Skipping '{}': {}.",
                                       entry.path().string(), ec.message()), 'r', true, std::cerr);
                ec.clear();
                continue;
            }
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
                    printColor(std::format("Skipping '{}': Not a regular file.",
                                           entry.path().string()), 'r', true, std::cerr);

            } else handleAccessError(entry.path().string());
        }
    }
}

/// \brief calculates hashes for a range of files.
/// \param files the files to process.
/// \param start the index where processing starts.
/// \param end the index where processing ends.
void calculateHashes(std::vector<FileInfo> &files, std::size_t start, std::size_t end) {
    // Check if the range is valid
    if (start > end || end > files.size())
        throw std::range_error("Invalid range.");

    // Calculate hashes for the files in the range
    for (std::size_t i = start; i < end; ++i)
        files[i].hash = calculateBlake3(files[i].path);
}

/// \brief finds duplicate files (by content) in a directory.
/// \param directoryPath the directory to process.
/// \return True if duplicates are found, else False.
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

    // Divide the files among the threads
    std::vector<std::jthread> threads;
    std::size_t filesPerThread = filesProcessed / numThreads;
    std::size_t start = 0;

    // Calculate the files' hashes in parallel
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

            for (const auto &filePath: duplicates) {
                std::cout << "  " << filePath << std::endl;
                ++numDuplicates;
            }
        }
    }
    printColor("\nFiles processed: ", 'c');
    printColor(filesProcessed, 'g', true);

    return numDuplicates;
}

/// \brief A simple duplicate file detective.
void duplicateFinder() {
    while (true) {
        std::cout << "\n-------------------";
        printColor(" Duplicate Finder ", 'm');
        std::cout << "-------------------\n";
        printColor("1. Scan for duplicate files\n", 'g');
        printColor("2. Exit\n", 'r');
        std::cout << "--------------------------------------------------------" << std::endl;

        printColor("Enter your choice:", 'b');
        int resp = getResponseInt();

        if (resp == 1) {
            try {
                printColor("Enter the path to the directory to scan:", 'b');
                std::string dirPath = getResponseStr();

                if (auto len = dirPath.size(); len > 1 && (dirPath.ends_with('/') || dirPath.ends_with('\\')))
                    dirPath.erase(len - 1);

                std::error_code ec;
                fs::file_status fileStatus = fs::status(dirPath, ec);
                if (ec) {
                    printColor("Unable to determine ", 'y', false, std::cerr);
                    printColor(dirPath, 'b', false, std::cerr);

                    printColor("'s status: ", 'y', false, std::cerr);
                    printColor(ec.message(), 'r', true, std::cerr);

                    ec.clear();
                    continue;
                }
                if (!fs::exists(fileStatus)) {
                    printColor(dirPath, 'c', false, std::cerr);
                    printColor(" does not exist.", 'r', true, std::cerr);
                    continue;
                }
                if (!fs::is_directory(fileStatus)) {
                    printColor(dirPath, 'c', false, std::cerr);
                    printColor(" is not a directory.", 'r', true, std::cerr);
                    continue;
                }

                if (fs::is_empty(dirPath, ec)) {
                    if (ec) ec.clear();
                    else {
                        printColor("The directory is empty.", 'r', true, std::cerr);
                        continue;
                    }
                }
                printColor("Scanning ", 'c');
                printColor(fs::canonical(dirPath).string(), 'g');
                printColor(" ...", 'c', true);
                std::size_t duplicateFiles = findDuplicates(dirPath);

                std::cout << "Duplicates "
                          << (duplicateFiles > 0 ? "found: " + std::to_string(duplicateFiles) : "not found.")
                          << std::endl;

            } catch (const std::exception &ex) {
                printColor("An error occurred: ", 'y', false, std::cerr);
                printColor(ex.what(), 'r', true, std::cerr);
                continue;
            }

        } else if (resp == 2) break;
        else {
            printColor("Invalid option!", 'r', true, std::cerr);
            continue;
        }
    }

}
