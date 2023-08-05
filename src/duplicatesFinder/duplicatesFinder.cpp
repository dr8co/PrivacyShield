#include <iostream>
#include <fstream>
#include <system_error>
#include <unistd.h>
#include <cerrno>
#include <thread>
#include <vector>
#include <unordered_map>
#include <filesystem>
#include <sodium.h>
#include <gcrypt.h>
#include <format>
#include "duplicatesFinder.hpp"
#include "../utils/utils.hpp"

namespace fs = std::filesystem;

constexpr size_t CHUNK_SIZE = 4096;  // Read and process files in chunks of 4 kB

/**
 * @brief Represents a file by its path (canonical) and hash.
 */
struct FileInfo {
    std::string path; // path to the file.
    std::string hash; // Blake2b hash of the file.
};

/**
 * @brief Calculates the BLAKE2 hash of a file.
 * On 64-bit architectures, the 512-bit BLAKE2b hash is calculated,
 * while the 256-bit BLAKE2s is calculated on 32-bit and other architectures.
 * The reason is that BLAKE2s hash algorithm is optimized
 * for 32-bit (and smaller) architectures.
 *
 * @param filePath path to the file.
 * @return a string of the hash of the file.
 */
std::string calculateBlake2Hash(const std::string &filePath) {
    // TODO: Consider using BLAKE3, which is much faster than BLAKE2 and is highly parallelizable, and is (almost) as secure.

    std::ifstream file(filePath, std::ios::binary);
    if (!file)
        throw std::runtime_error("Failed to open: " + filePath + " for hashing.");

    std::vector<char> buffer(CHUNK_SIZE);

#if __x86_64 or __x86_64__ or __amd64 or __amd64__ or _M_X64 or _M_AMD64 or __LP64__ // 64-bit system: use BLAKE2b

    crypto_generichash_blake2b_state state;

    // Initialize the hashing process with the state, and set the output length to 512 bits (64 bytes)
    if (crypto_generichash_blake2b_init(&state, nullptr, 0, crypto_generichash_BYTES_MAX) != 0)
        throw std::runtime_error("Failed to initialize Blake2b hashing.");

    // Hash the file in chunks of 4 kB
    while (file.read(buffer.data(), CHUNK_SIZE)) {
        if (crypto_generichash_blake2b_update(&state,
                                              reinterpret_cast<const unsigned char *>(buffer.data()),
                                              CHUNK_SIZE) != 0)
            throw std::runtime_error("Failed to calculate Blake2b hash.");
    }

    // Hash the last chunk of data
    size_t remainingBytes = file.gcount();
    if (crypto_generichash_blake2b_update(&state,
                                          reinterpret_cast<const unsigned char *>(buffer.data()),
                                          remainingBytes) != 0)
        throw std::runtime_error("Failed to calculate Blake2b hash.");

    // Finalize the hash calculation
    std::vector<unsigned char> digest(crypto_generichash_BYTES_MAX);
    if (crypto_generichash_blake2b_final(&state, digest.data(), crypto_generichash_BYTES_MAX) != 0)
        throw std::runtime_error("Failed to finalize Blake2b hash calculation.");

    file.close();

#else   // 32-bit (or smaller) system: use BLAKE2s

    gcry_error_t err;
    gcry_md_algos algo = GCRY_MD_BLAKE2S_256; // 256-bit Blake 2s hash algorithm

    // Create the hash context handle
    gcry_md_hd_t handle;

    size_t mdLength = gcry_md_get_algo_dlen(algo);

    // Create a message digest object for the algorithm
    err = gcry_md_open(&handle, algo, 0);
    if (err)
        throw std::runtime_error("Failed to create digest handle: " + std::string(gcry_strerror(err)));

    // Calculate the hash in chunks
    while (file.read(buffer.data(), CHUNK_SIZE)) {
        gcry_md_write(handle, buffer.data(), CHUNK_SIZE);
    }
    // update the hash with the last chunk of data
    size_t remainingBytes = file.gcount();
    gcry_md_write(handle, buffer.data(), remainingBytes);

    file.close(); // We're done with the file

    // Finalize the message digest calculation and read the digest
    std::vector<unsigned char> digest(mdLength);
    unsigned char *tmp = gcry_md_read(handle, algo);

    // Base64-encode the hash, so it can be easily handled as a string
    digest.assign(tmp, tmp + mdLength);

    // Release all the resources associated with the hash context
    gcry_md_close(handle);

#endif

    // Since the hash is raw bytes, Base64-encode it for string handling
    std::string blake2Hash(base64Encode(digest));

    return blake2Hash;
}

/**
 * @brief recursively traverses a directory and collects file information.
 * @param directoryPath the directory to process.
 * @param files a vector to store the information from the files found in the directory.
 */
void traverseDirectory(const std::string &directoryPath, std::vector<FileInfo> &files) {
    // Check if the directory exists
    if (!fs::exists(directoryPath))
        throw std::runtime_error(std::format("Directory: '{}' does not exist.", directoryPath));
    else if (!fs::is_directory(directoryPath))
        throw std::runtime_error(std::format("'{}' is not a directory.", directoryPath));
    else if (fs::is_empty(directoryPath)) {
        std::cout << std::format("Directory: '{}' is empty.", directoryPath) << std::endl;
        return;
    }

//    std::error_code ec;
    for (const auto &entry: fs::recursive_directory_iterator(directoryPath,
                                                             fs::directory_options::skip_permission_denied)) {

        // Make sure we can read the entry
        if (access(entry.path().c_str(), F_OK | R_OK) == 0) [[likely]] {

//        if (static_cast<bool>((entry.status(ec).permissions() &   // platform-independent but doesn't directly provide
//                                                                  // a built-in way to check file permissions based on the
//                                                                  // current user's ownership
//                               (fs::perms::owner_read | fs::perms::group_read | fs::perms::others_read)))) {

            // process only regular files
            if (entry.is_regular_file()) [[likely]] {
                FileInfo fileInfo;

                // Update the file details
                fileInfo.path = entry.path().string();
                fileInfo.hash = "";  // the hash will be calculated later
                files.push_back(fileInfo);

            } else if (!entry.is_directory()) // Neither regular nor a directory
                std::cerr << std::format("Skipping '{}': Not a regular file.", entry.path().string()) << std::endl;

        } else {
            switch (errno) {
                case EACCES:
                    std::cerr << std::format("Skipping '{}': Insufficient read permissions.", entry.path().string())
                              << std::endl;
                    break;
                case ENOENT:
                    std::cerr << std::format("Skipping '{}': File not found.", entry.path().string()) << std::endl;
                    break;
                default:
                    std::perror(std::format("Skipping \"{}\"", entry.path().string()).c_str());
            }
        }
        // Log the error encountered in fs::status() call, if any
//        if (ec) {
//            std::cerr << ec.message() << std::endl;
//            ec.clear();
//        }

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
        throw std::runtime_error("Invalid range.");

    for (size_t i = start; i < end; ++i) {
        files[i].hash = calculateBlake2Hash(files[i].path);
    }
}

/**
 * @brief finds duplicate files (by content) in a directory.
 * @param directoryPath - the directory to process.
 * @return True if duplicates are found, else False.
 */
size_t findDuplicates(const std::string &directoryPath) {
    if (sodium_init() == -1) {
        throw std::runtime_error("Failed to initialize libsodium.");
    }

    // Collect file information
    std::vector<FileInfo> files;
    traverseDirectory(directoryPath, files);
    size_t filesProcessed = files.size();
    if (filesProcessed < 1) return 0;

    // Number of threads to use
    const unsigned int numThreads{std::thread::hardware_concurrency() ? std::thread::hardware_concurrency() : 8};

    // Divide files among threads
    std::vector<std::thread> threads;
    size_t filesPerThread = filesProcessed / numThreads;
    size_t start = 0;

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

    size_t duplicatesSet = 0, numDuplicates = 0;

    // Display duplicate files
    std::cout << "Duplicates found:" << std::endl;
    for (const auto &pair: hashMap) {
        const std::vector<std::string> &duplicates = pair.second;

        if (duplicates.size() > 1) {
            ++duplicatesSet;

            // Show the duplicates in their sets
            std::cout << "Duplicate files set " << duplicatesSet << ":" << std::endl;
            for (const std::string &filePath: duplicates) {
                std::cout << "  " << filePath << std::endl;
                ++numDuplicates;
            }
        }
    }
    std::cout << "\nFiles processed: " << filesProcessed << std::endl;

    return numDuplicates;
}
