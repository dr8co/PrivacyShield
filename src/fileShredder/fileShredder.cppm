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

#include<cstring>
#include <fstream>
#include <random>
#include <filesystem>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <format>
#include <iostream>
#include <utility>
#include <print>

using StatType = struct stat;

export module fileShredder;
import utils;

namespace fs = std::filesystem;
constexpr std::streamoff BUFFER_SIZE = 4096;


/// \brief overwrites a file with random bytes.
/// \param file output file stream object.
/// \param fileSize the size of the file in bytes.
/// \param nPasses the number of passes to overwrite the file.
///
/// \throws std::runtime_error if the \p file is not open, or if there is a file write error.
void overwriteRandom(std::ofstream &file, const std::size_t fileSize, const int nPasses = 1) {
    if (!file.is_open()) throw std::runtime_error("File not open.");
    // Instantiate the random number generator
    std::random_device rd;
    std::uniform_int_distribution<unsigned char> dist(0, 255);

    for (int i = 0; i < nPasses; ++i) {
        // seek to the beginning of the file
        file.seekp(0, std::ios::beg);

        // (Re)seed the Mersenne Twister engine in every pass
        std::mt19937_64 gen(rd());

        std::vector<unsigned char> buffer(BUFFER_SIZE);

        // Overwrite the file with random data
        for (std::size_t pos = 0; pos < fileSize; pos += BUFFER_SIZE) {
            // Generate a buffer filled with random data
            for (auto &byte: buffer) {
                byte = dist(gen);
            }
            // Adjust the buffer size for the last chunk of data, which may be smaller than the buffer size
            if (pos + BUFFER_SIZE > fileSize) {
                buffer.resize(fileSize - pos);
            }

            file.write(reinterpret_cast<char *>(buffer.data()), static_cast<std::streamsize>(buffer.size()));

            if (!file) {
                throw std::runtime_error("file write error");
            }
        }
    }
}

/// \brief overwrites a file wih a constant byte.
/// \tparam T type of the byte.
/// \param file output file stream object to overwrite.
/// \param byte the byte to overwrite the file with.
/// \param fileSize the size of the file in bytes.
///
/// \throws std::runtime_error if the \p file is not open, or if there is a file write error.
template<typename T>
void overwriteConstantByte(std::ofstream &file, T &byte, const auto &fileSize) {
    if (!file.is_open()) throw std::runtime_error("File not open.");
    // seek to the beginning of the file
    file.seekp(0, std::ios::beg);

    std::vector<T> buffer(BUFFER_SIZE, byte);

    for (std::streamoff pos = 0; pos < fileSize; pos += BUFFER_SIZE) {
        if (pos + BUFFER_SIZE > fileSize) {
            buffer.resize(fileSize - pos);
        }
        file.write(reinterpret_cast<char *>(buffer.data()), static_cast<std::streamsize>(buffer.size()));

        if (!file) throw std::runtime_error("file write error.");
    }
}

/// \brief renames a file to a random name before removing it.
/// \param filename the path to the file to be renamed.
/// \param numTimes the number of times to rename the file.
inline void renameAndRemove(const std::string_view filename, int numTimes = 1) {
    constexpr int maxTries = 10; // max number of trials to rename the file
    constexpr int minNameLength = 3; // min length of the random name
    constexpr int maxNameLength = 16; // max length of the random name

    // Check if the number of times is valid
    if (numTimes < 1) return;
    if (numTimes > maxTries) numTimes = maxTries;

    // Create an instance of the random device for generating secure random numbers
    std::random_device rd;

    // Mersenne Twister engine seeded with rd
    std::mt19937 gen(rd());

    // Distribution for the number of characters in the new name
    std::uniform_int_distribution<int> numDist(minNameLength, maxNameLength);

    // Get the file extension using std::filesystem
    const std::string fileExtension = fs::path(filename).extension().string();

    // Generate a random name using the safe characters (Not exhaustive)
    const std::string safeChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    std::uniform_int_distribution<std::size_t> dist(0, safeChars.size() - 1);

    fs::path path(filename);
    std::error_code ec;

    // (Try to) rename the file numTimes times
    for (int i = 0; i < numTimes; ++i) {
        if (i >= maxTries) break; // Give up after 10 tries
        fs::path tmpPath = path; // Track renaming

        // Generate a random number of characters for the new name
        const int numChars = numDist(gen);

        std::string newName;
        // Generate a random name
        for (int j = 0; j < numChars; ++j)
            newName += safeChars[dist(gen)];
        newName += fileExtension; // preserve the file extension
        path.replace_filename(newName);

        // Rename the file if it doesn't exist to avoid overwriting existing files
        if (!exists(path)) {
            fs::rename(tmpPath, path, ec);
            // Try again if there was an error
            if (ec) {
                ++numTimes;
                ec.clear();
            }
        } else ++numTimes; // Try again, the file already exists
    }

    fs::remove(path, ec);
    if (ec) {
        printColoredError('r', "Failed to delete ");
        printColoredError('m', "{}", filename);
        printColoredErrorln('r', ": {}", ec.message());
    }
}

/// \struct FileDescriptor
/// \brief Represents a file descriptor.
///
/// The FileDescriptor class provides a convenient way to manage a file descriptor. It automatically opens the file
/// with the specified filename upon initialization, and closes the file when the object is destroyed. If the file
/// open operation fails, a runtime_error exception is thrown.
struct FileDescriptor {
    int fd{-1};

    explicit FileDescriptor(const std::string &filename) : fd(open(filename.c_str(), O_RDWR)) {
        if (fd == -1)
            throw std::runtime_error("Failed to open file: " + filename + " (" + std::strerror(errno) + ")");
    }

    ~FileDescriptor() { if (fd != -1) close(fd); }
};

/// \struct FileStatInfo
/// \brief Provides information about a file based on its file descriptor.
///
/// The FileStatInfo struct encapsulates the information obtained from the stat function
/// for a given file descriptor. It provides a simple way to access file attributes such as
/// file size, permissions, and timestamps.
struct FileStatInfo {
    StatType fileStat{};

    explicit FileStatInfo(const int &fileDescriptor) {
        if (fstat(fileDescriptor, &fileStat) == -1)
            throw std::runtime_error(std::format("Failed to get file size: ({})", std::strerror(errno)));
    }
};

/// \brief wipes the cluster tips of a file.
/// \param fileName the path to the file to be wiped.
/// \throws std::runtime_error if zeroing the cluster tips fails.
inline void wipeClusterTips(const std::string &fileName) {
    const FileDescriptor fileDescriptor(fileName);
    const FileStatInfo fileInformation(fileDescriptor.fd);

    // Calculate the size of the cluster tip
    auto clusterTipSize = fileInformation.fileStat.st_blksize -
                          (fileInformation.fileStat.st_size % fileInformation.fileStat.st_blksize);

    if (clusterTipSize >= fileInformation.fileStat.st_size) {
        clusterTipSize = 0;
    }
    // Seek to the end of the file
    if (lseek(fileDescriptor.fd, 0, SEEK_END) == -1) {
        throw std::runtime_error(std::format("Failed to seek to end of file: ({})", std::strerror(errno)));
    }

    // Write zeros to the cluster tip
    const std::vector<char> zeroBuffer(clusterTipSize, 0);

    if (write(fileDescriptor.fd, zeroBuffer.data(), zeroBuffer.size()) == static_cast<ssize_t>(-1)) {
        throw std::runtime_error(std::format("Failed to write zeros: ({})", std::strerror(errno)));
    }
}

/// \brief shreds a file by overwriting it with random bytes.
/// \param filename path to the file being overwritten.
/// \param nPasses the number of passes to overwrite the file.
/// \param wipeClusterTip whether to wipe the cluster tips of the file.
///
/// \throws std::runtime_error if the file cannot be opened.
void simpleShred(const std::string &filename, const int &nPasses = 3, const bool wipeClusterTip = false) {
    std::ofstream file(filename, std::ios::binary | std::ios::in);
    if (!file)
        throw std::runtime_error("\nFailed to open file: " + filename);

    std::error_code ec;
    // Read last write time
    const auto initTime = fs::last_write_time(filename, ec);
    if (ec) ec.clear();

    // Get the file size
    file.seekp(0, std::ios::end);
    const std::streamoff fileSize = file.tellp();
    file.seekp(0, std::ios::beg);

    // Shred the file
    overwriteRandom(file, fileSize, nPasses);

    file.close();
    if (wipeClusterTip) wipeClusterTips(filename);

    // Restore last write time
    last_write_time(filename, initTime, ec);

    // Rename and remove the file
    renameAndRemove(filename, 3);
}

/// \brief shreds a file using a simple version of
/// The U.S Department of Defence (DoD) 5220.22-M Standard algorithm.
/// \param filename - the path to the file to be shred.
/// \param nPasses the number of passes to overwrite the file.
/// \param wipeClusterTip whether to wipe the cluster tips of the file.
///
/// \throws std::runtime_error if the file cannot be opened, or if the number of passes is invalid.
void dod5220Shred(const std::string &filename, const int &nPasses = 3, const bool wipeClusterTip = false) {
    std::ofstream file(filename, std::ios::binary | std::ios::in);
    if (!file)
        throw std::runtime_error("\nFailed to open file: " + filename);

    std::error_code ec;
    // Read last write time
    const auto initTime = fs::last_write_time(filename, ec);
    if (ec) ec.clear();

    // Get the file size
    file.seekp(0, std::ios::end);
    std::streamoff fileSize = file.tellp();
    file.seekp(0, std::ios::beg);

    // The DoD 5220.22-M Standard algorithm
    auto dod3Pass = [&file, &fileSize] -> void {
        unsigned char zeroByte = 0x00;
        unsigned char oneByte = 0xFF;
        // Pass 1: Overwrite with zeros
        overwriteConstantByte(file, zeroByte, fileSize);

        // Pass 2: Overwrite with ones
        overwriteConstantByte(file, oneByte, fileSize);

        // Pass 3: Overwrite with random data
        overwriteRandom(file, fileSize);
    };

    if (nPasses == 3) {
        dod3Pass();
    } else if (nPasses == 7) {
        dod3Pass();
        overwriteRandom(file, fileSize);
        dod3Pass();
    } else throw std::runtime_error("\nInvalid number of passes: " + std::to_string(nPasses));

    if (file.is_open()) file.close();

    // Wipe cluster tips, if required
    if (wipeClusterTip) wipeClusterTips(filename);

    // Restore last write time
    last_write_time(filename, initTime, ec);
    if (ec) ec.clear();

    // Rename and remove the file
    renameAndRemove(filename, 3);
}

/// \enum ShredOptions
/// \brief Represents the different shredding options.
enum class ShredOptions : std::uint_fast8_t {
    Simple          = 1 << 0, ///< Simple overwrite with random bytes
    Dod5220         = 1 << 1, ///< DoD 5220.22-M Standard algorithm
    Dod5220_7       = 1 << 2, ///< DoD 5220.22-M Standard algorithm with 7 passes
    WipeClusterTips = 1 << 3  ///< Wiping of the cluster tips
};

/// \brief Adds write and write permissions to a file, if the user has authority.
/// \param fileName The file to modify.
/// \return True if the operation succeeds, else false.
///
/// \details The actions of this function are similar to the unix command:
/// \code chmod ugo+rw fileName \endcode or \code chmod a+rw fileName \endcode. \n
/// The read/write permissions are added for everyone.
/// \note This function is meant for the file shredder ONLY, which might
/// need to modify a file's permissions (if and only if it has to) to successfully shred it.
///
/// \warning Modifying file permissions unnecessarily is a serious security risk,
/// and this program doesn't take that for granted.
static inline bool addReadWritePermissions(const std::string_view fileName) noexcept {
    std::error_code ec;
    permissions(fileName, fs::perms::owner_read | fs::perms::owner_write | fs::perms::group_read |
                          fs::perms::group_write | fs::perms::others_read | fs::perms::others_write,
                fs::perm_options::add, ec);
    return !ec;
}

/// \brief shreds a file (or all files and subdirectories of a directory)
/// using the specified options.
/// \param filePath - the path to the file to be shred.
/// \param options - the options to use when shredding the file.
/// \param simplePasses - the number of passes for random overwrite
/// for simple shredding.
/// \return true if the file (or directory) was shred successfully, false otherwise.
///
/// \throws std::runtime_error if the shred options are invalid, or if the file cannot be shredded.
///
/// \warning If the filePath is a directory, then all its files and subdirectories
/// are shredded without warning.
bool shredFiles(const std::string &filePath, const std::uint_fast8_t &options, const int &simplePasses = 3) {
    std::error_code ec;
    const fs::file_status fileStatus = fs::status(filePath, ec);
    if (ec) {
        printColoredError('y', "Unable to determine ");
        printColoredError('b', "{}", filePath);

        printColoredError('y', "'s status: ");
        printColoredErrorln('r', "{}", ec.message());
        return false;
    }
    // Check if the file exists and is a regular file.
    if (!exists(fileStatus)) {
        printColoredError('c', "{}", filePath);
        printColoredErrorln('r', " does not exist.");
        return false;
    }
    // If the filepath is a directory, shred all the files in the directory and all its subdirectories
    if (is_directory(fileStatus)) {
        if (fs::is_empty(filePath, ec)) {
            if (ec) ec.clear();
            else {
                printColoredOutput('c', "{}", filePath);
                printColoredOutputln('y', " is an empty directory.");
                return true;
            }
        }
        static std::size_t numShredded{0}, numNotShredded{0};

        // Shred all files in the directory and all subdirectories
        for (const auto &entry: fs::recursive_directory_iterator(filePath)) {
            if (entry.exists(ec)) {
                if (ec) {
                    printColoredErrorln('r', "{}", ec.message());
                    ec.clear();
                    continue;
                }
                if (!is_directory(entry.status())) {
                    printColoredOutput('c', "Shredding ");
                    printColoredOutput('b', "{}", canonical(entry.path()).string());
                    printColoredOutput('c', " ...");
                    try {
                        const bool shredded = shredFiles(entry.path().string(), options);
                        printColoredOutputln(shredded ? 'g' : 'r', "{}",
                                             shredded ? "\tshredded successfully." : "\tshredding failed.");

                        ++(shredded ? numShredded : numNotShredded);
                    } catch (const std::runtime_error &err) {
                        printColoredError('y', "Shredding failed: ");
                        printColoredErrorln('r', "{}", err.what());
                    }
                }
            }
        }
        if (numNotShredded == 0) // All files in the directory and all subdirectories were shredded successfully.
            remove_all(fs::canonical(filePath));
        else printColoredErrorln('r', "Failed to shred some files.");

        std::println("\nProcessed  {} files.", numShredded + numNotShredded);
        if (numShredded) {
            printColoredOutput('g', "Successfully shredded and deleted: ");
            printColoredOutputln('b', "{}", numShredded);
        }
        if (numNotShredded) {
            printColoredError('r', "Failed to shred ");
            printColoredError('b', "{}", numNotShredded);
            printColoredErrorln('r', " files.");
        }

        return true;
    }
    if (!is_regular_file(fileStatus)) {
        printColoredError('c', "{}", filePath);
        printColoredError('r', " is not a regular file.");
        printColoredOutputln('y', "Do you want to (try to) shred the file anyway? (y/n):");

        if (!validateYesNo()) return false;
    }

    // Check file permissions
    if (!isWritable(filePath) || !isReadable(filePath)) {
        if (!addReadWritePermissions(filePath)) {
            printColoredError('r', "\nInsufficient permissions to shred file: ");
            printColoredErrorln('c', "{}", filePath);
            return false;
        }
    }
    // shred the file according to the options
    if (const std::uint_fast8_t wipeTips = options & std::to_underlying(ShredOptions::WipeClusterTips);
        options & std::to_underlying(ShredOptions::Simple))
        simpleShred(filePath, simplePasses, wipeTips);
    else if (options & std::to_underlying(ShredOptions::Dod5220))
        dod5220Shred(filePath, 3, wipeTips);
    else if (options & std::to_underlying(ShredOptions::Dod5220_7))
        dod5220Shred(filePath, 7, wipeTips);
    else throw std::runtime_error("Invalid shred options.");

    return true;
}

/// \brief A simple file shredder.
export void fileShredder() {
    // Configures the shredding options.
    auto selectPreferences = [](std::uint_fast8_t &preferences, int &simpleNumPass) {
        const int moreChoices1 = getResponseInt("\n1. Continue with default shredding options\n"
            "2. Configure shredding options");
        const std::uint_fast8_t &wipeTips = std::to_underlying(ShredOptions::WipeClusterTips);

        if (moreChoices1 == 1) {
            // Default options: simple shredding with random bytes, and wipe cluster tips.
            preferences |= std::to_underlying(ShredOptions::Simple) | wipeTips;
        } else if (moreChoices1 == 2) {
            // Configure shredding options
            if (const int alg = getResponseInt("\nChoose a shredding algorithm:\n"
                "1. Overwrite with random bytes (default)\n"
                "2. 3-pass DoD 5220.22-M Standard algorithm\n"
                "3. 7-pass DoD 5220.22-M Standard algorithm"); alg == 1) {
                preferences |= std::to_underlying(ShredOptions::Simple) | wipeTips;

                do {
                    const int simpleConfig = getResponseInt("\n1. Continue\n"
                        "2. Change the number of passes (default is 3)\n"
                        "3. Configure wiping of cluster tips (enabled by default)\n"
                        "4. Abort");

                    if (simpleConfig == 1) break; // Continue
                    if (simpleConfig == 2) {
                        // Change the number of passes
                        simpleNumPass = getResponseInt(
                            "How many times would you like to overwrite? (3 times is recommended.)");

                        if (simpleNumPass > 10) throw std::length_error("Too many passes.");
                        if (simpleNumPass < 1) throw std::length_error("Number of passes should be at least 1.");
                    } else if (simpleConfig == 3) {
                        // Configure wiping of cluster tips
                        preferences = (preferences & ~wipeTips) |
                                      (-validateYesNo("Wipe cluster tips? (Recommended) (y/n):") & wipeTips);
                    } else if (simpleConfig == 4) {
                        // Abort
                        throw std::runtime_error("Operation aborted.");
                    } else printColoredErrorln('r', "Invalid option");
                } while (true);
            } else if (alg == 2 || alg == 3) {
                // DoD 5220.22-M Standard algorithms
                preferences |= std::to_underlying(alg == 2 ? ShredOptions::Dod5220 : ShredOptions::Dod5220_7);

                preferences = (preferences & ~wipeTips) |
                              (-validateYesNo("Wipe cluster tips? (Recommended) (y/n):") & wipeTips);
            } else throw std::invalid_argument("Invalid option");
        } else throw std::invalid_argument("Invalid option");
    };

    while (true) {
        printColoredOutput('g', "\n------------------");
        printColoredOutput('m', " file shredder ");
        printColoredOutputln('g', "------------------");

        printColoredOutputln('y', "1. Shred a file");
        printColoredOutputln('y', "2. Shred a directory");
        printColoredOutputln('r', "3. Exit");

        printColoredOutputln('g', "---------------------------------------------------");

        if (const int choice = getResponseInt("Enter your choice: "); choice == 1 || choice == 2) {
            try {
                // Get the path to the file or directory to shred
                fs::path path = getFilesystemPath(std::format("Enter the path to the {} you would like to shred:",
                                                              choice == 1 ? "file" : "directory").c_str());

                std::error_code ec;
                const fs::file_status fileStatus = fs::status(path, ec);
                if (ec) {
                    printColoredErrorln('r', "{}", ec.message());
                    ec.clear();
                    continue;
                }
                const bool isDir{is_directory(fileStatus)};
                auto canonicalPath = fs::weakly_canonical(path).string();

                // Check if the file or directory exists
                if (!exists(fileStatus)) {
                    printColoredError('c', "{}", canonicalPath);
                    printColoredErrorln('r', " does not exist.");
                    continue;
                }
                // If the path is a directory, shred all the files in the directory and all subdirectories (with confirmation)
                if (choice == 1 && isDir) {
                    printColoredOutput('c', "{}", canonicalPath);
                    printColoredOutputln('r', " is a directory.");

                    printColoredOutput('y', "Shred all files in '");
                    printColoredOutput('c', "{}", canonicalPath);
                    printColoredOutputln('y', "'\nand all its subdirectories? (y/n):");
                    if (!validateYesNo()) continue;
                } else if (choice == 2 && !isDir) {
                    // If the path is a file, shred it without confirmation
                    printColoredOutput('c', "{}", canonicalPath);
                    printColoredOutputln('r', " is not a directory.");
                    if (!validateYesNo("Shred it anyway? (y/n):")) continue;
                }
                std::uint_fast8_t preferences{0};
                int simpleNumPass{3};
                // Select shredding preferences
                try {
                    selectPreferences(preferences, simpleNumPass);
                } catch (const std::exception &ex) {
                    printColoredErrorln('r', "Error: {}", ex.what());
                    continue;
                }

                printColoredOutputln('r', "The {} contents will be lost permanently.\nContinue? (y/n)",
                                     isDir ? "directory's (and all its subdirectories')" : "file");
                if (validateYesNo()) {
                    std::cout << "Shredding '";
                    printColoredOutput('c', "{}", canonicalPath);
                    std::cout << "'..." << std::endl;
                    const bool shredded = shredFiles(path, preferences, simpleNumPass);
                    if (!isDir) {
                        printColoredOutput(shredded ? 'g' : 'r', "{}",
                                           shredded ? "Successfully shredded " : "Failed to shred ");
                        printColoredOutputln('c', "{}", canonicalPath);
                    }
                }
            } catch (const std::exception &err) {
                printColoredErrorln('r', "Error: {}", err.what());
            }
        } else if (choice == 3) break;
        else printColoredErrorln('r', "Invalid choice.");
    }
}
