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

#include <print>
#include <fstream>
#include <system_error>
#include <thread>
#include <vector>
#include <unordered_map>
#include <filesystem>
#include <blake3.h>
#include <cstring>
#include <format>
#include <ranges>

export module duplicateFinder;
import utils;

namespace fs = std::filesystem;

constexpr std::size_t CHUNK_SIZE = 4096; ///< Read and process files in chunks of 4 kB


/// \brief Represents a file by its path (canonical) and hash.
struct FileInfo {
    std::string path; ///< the path to the file.
    std::string hash; ///< the file's BLAKE3 hash
};

/// \brief Calculates the 256-bit BLAKE3 hash of a file.
/// \param filePath path to the file.
/// \return Base64-encoded hash of the file.
/// \throws std::runtime_error if the file cannot be opened.
std::string calculateBlake3(const std::string &filePath) {
    // Open the file
    std::ifstream file(filePath, std::ios::binary);
    if (!file) {
        if (std::error_code ec; fs::exists(filePath, ec))
            throw std::runtime_error(std::format("Failed to open '{}' for hashing.", filePath));

        printColoredError('b', "{} ", filePath);
        printColoredErrorln('r', "existed during scan but was not found during hashing.");
        return "";
    }

    // Initialize the BLAKE3 hasher
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);

    // Update the hasher with the file contents in chunks of 4 kB
    std::array<char, CHUNK_SIZE> buffer{};
    while (file.read(buffer.data(), CHUNK_SIZE))
        blake3_hasher_update(&hasher, buffer.data(), CHUNK_SIZE);

    // Update the hasher with the last chunk of data
    const std::size_t remainingBytes = file.gcount();
    blake3_hasher_update(&hasher, buffer.data(), remainingBytes);

    // Finalize the hash calculation
    std::vector<unsigned char> digest(BLAKE3_OUT_LEN);
    blake3_hasher_finalize(&hasher, digest.data(), BLAKE3_OUT_LEN);

    return base64Encode(digest);
}

/// \brief handles file i/o errors during low-level file operations.
/// \param filename path to the file on which an error occurred.
inline void handleAccessError(const std::string_view filename) {
    if (errno) {
        printColoredError('r', "Skipping ");
        printColoredError('c', "{}", filename);
        printColoredErrorln('r', ": {}", std::strerror(errno));

        errno = 0;
    }
}

/// \brief recursively traverses a directory and collects file information.
/// \param directoryPath the directory to process.
/// \param files a vector to store the information from the files found in the directory.
void traverseDirectory(const fs::path &directoryPath, std::vector<FileInfo> &files) {
    std::error_code ec;

    for (const auto &entry: fs::recursive_directory_iterator(directoryPath,
                                                             fs::directory_options::skip_permission_denied |
                                                             fs::directory_options::follow_directory_symlink)) {
        if (entry.exists(ec)) {
            // In case of broken symlinks
            if (ec) {
                printColoredError('r', "Skipping ");
                printColoredError('c', "{}", entry.path().string());
                printColoredErrorln('r', ": {}", ec.message());
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
                    fileInfo.hash = ""; // the hash will be calculated later
                    files.emplace_back(fileInfo);
                } else if (!entry.is_directory()) {
                    // Neither regular nor a directory
                    printColoredError('r', "Skipping ");
                    printColoredError('c', "{}", entry.path().string());
                    printColoredErrorln('r', ": Not a regular file.", ec.message());
                }
            } else handleAccessError(entry.path().string());
        }
    }
}

/// \brief calculates hashes for a range of files.
/// \param files the files to process.
/// \param start the index where processing starts.
/// \param end the index where processing ends.
void calculateHashes(std::vector<FileInfo> &files, const std::size_t start, const std::size_t end) {
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
std::size_t findDuplicates(const fs::path &directoryPath) {
    // Collect file information
    std::vector<FileInfo> files;
    traverseDirectory(directoryPath, files);
    const std::size_t filesProcessed = files.size();
    if (filesProcessed < 2) return 0;

    // Number of threads to use
    const unsigned int n{std::jthread::hardware_concurrency()};
    const unsigned int numThreads{n ? n : 8}; // Use 8 threads if hardware_concurrency() fails

    // Divide the files among the threads
    std::vector<std::jthread> threads;
    const std::size_t filesPerThread = filesProcessed / numThreads;
    std::size_t start = 0;

    // Calculate the files' hashes in parallel
    for (int i = 0; i < static_cast<int>(numThreads - 1); ++i) {
        threads.emplace_back(calculateHashes, std::ref(files), start, start + filesPerThread);
        start += filesPerThread;
    }
    // The last thread may handle slightly more files to account for the division remainder
    threads.emplace_back(calculateHashes, std::ref(files), start, files.size());

    // Wait for all threads to finish execution
    for (auto &thread: threads) thread.join();

    // A hash map to map the files to their corresponding hashes
    std::unordered_map<std::string, std::vector<std::string> > hashMap;

    // Iterate over files and identify duplicates
    for (const auto &[filePath, hash]: files)
        hashMap[hash].push_back(filePath);

    std::size_t duplicatesSet{0}, numDuplicates{0};

    // Display duplicate files
    std::println("Duplicates found:");
    for (const auto &duplicates: hashMap | std::views::values) {
        if (duplicates.size() > 1) {
            ++duplicatesSet;

            // Show the duplicates in their sets
            printColoredOutput('c', "Duplicate files set ");
            printColoredOutput('g', "{}", duplicatesSet);
            printColoredOutputln('c', ":");

            for (const auto &filePath: duplicates) {
                ++numDuplicates;
                std::println("  {}", filePath);
            }
        }
    }
    printColoredOutput('c', "\nFiles processed: ");
    printColoredOutputln('g', "{}", filesProcessed);

    return numDuplicates;
}

/// \brief A simple duplicate file detective.
export void duplicateFinder() {
    while (true) {
        std::print("\n-------------------");
        printColoredOutput('m', " Duplicate Finder ");
        std::println("-------------------");
        printColoredOutputln('g', "1. Scan for duplicate files");
        printColoredOutputln('r', "2. Exit");
        std::println("--------------------------------------------------------");

        printColoredOutput('b', "Enter your choice:");

        if (const int resp = getResponseInt(); resp == 1) {
            try {
                printColoredOutput('b', "Enter the path to the directory to scan:");
                fs::path dirPath = getFilesystemPath();

                std::error_code ec;
                const fs::file_status fileStatus = fs::status(dirPath, ec);
                if (ec) {
                    printColoredError('y', "Unable to determine ");
                    printColoredError('b', "{}", dirPath.string());

                    printColoredError('y', "'s status: ");
                    printColoredErrorln('r', "{}", ec.message());

                    ec.clear();
                    continue;
                }
                if (!exists(fileStatus)) {
                    printColoredError('c', "{}", dirPath.string());
                    printColoredErrorln('r', " does not exist.");
                    continue;
                }
                if (!is_directory(fileStatus)) {
                    printColoredError('c', "{}", dirPath.string());
                    printColoredErrorln('r', " is not a directory.");
                    continue;
                }

                if (fs::is_empty(dirPath, ec)) {
                    if (ec) ec.clear();
                    else {
                        printColoredErrorln('r', "The directory is empty.");
                        continue;
                    }
                }
                printColoredOutput('c', "Scanning ");
                printColoredOutput('g', "{}", fs::canonical(dirPath).string());
                printColoredOutputln('c', " ...");
                const std::size_t duplicateFiles = findDuplicates(dirPath);

                std::println("Duplicates {}",
                             duplicateFiles > 0 ? "found: " + std::to_string(duplicateFiles) : "not found.");
            } catch (const std::exception &ex) {
                printColoredError('y', "An error occurred: ");
                printColoredErrorln('r', "{}", ex.what());
            }
        } else if (resp == 2) break;
        else {
            printColoredErrorln('r', "Invalid option!");
        }
    }
}
