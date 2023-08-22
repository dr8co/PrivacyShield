#include <iostream>
#include <fstream>
#include <random>
#include <filesystem>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <format>
#include "shredFiles.hpp"
#include "../utils/utils.hpp"

namespace fs = std::filesystem;

/**
 * @brief overwrites a file with random bytes.
 * @param file output file stream object.
 * @param fileSize the size of the file in bytes.
 * @param nPasses the number of passes to overwrite the file.
 */
void overwriteRandom(std::ofstream &file, const std::size_t fileSize, int nPasses = 1) {

    // Instantiate the random number generator
    std::random_device rd;
    std::uniform_int_distribution<unsigned char> dist(0, 255);

    for (int i = 0; i < nPasses; ++i) {
        // (Re)seed the Mersenne Twister engine in every pass
        std::mt19937_64 gen(rd());

        // seek to the beginning of the file
        file.seekp(0, std::ios::beg);

        // Overwrite the file with random data
        for (std::size_t pos = 0; pos < fileSize; ++pos) {
            unsigned char randomByte = dist(gen);
            file.write(reinterpret_cast<char *>(&randomByte), sizeof(decltype(randomByte)));
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
void overwriteConstantByte(std::ofstream &file, T byte, const auto &fileSize) {
    // seek to the beginning of the file
    file.seekp(0, std::ios::beg);

    for (std::streamoff pos = 0; pos < fileSize; ++pos) {
        file.write(reinterpret_cast<char *>(&byte), sizeof(T));
    }
}

/**
 * @brief renames a file to a random name before removing it.
 * @param filename the path to the file to be renamed.
 * @param numTimes the number of times to rename the file.
 */
inline void renameAndRemove(const std::string &filename, int numTimes = 1) {
    constexpr int maxTries = 10;        // max number of trials to rename the file
    constexpr int minNameLength = 3;    // min length of the random name
    constexpr int maxNameLength = 16;   // max length of the random name

    // Check if the number of times is valid
    if (numTimes < 1) return;
    else if (numTimes > maxTries) numTimes = maxTries;

    // Create an instance of the random device for generating secure random numbers
    std::random_device rd;

    // Mersenne Twister engine seeded with rd
    std::mt19937 gen(rd());

    // Distribution for the number of characters in the new name
    std::uniform_int_distribution<int> numDist(minNameLength, maxNameLength);

    // Get the file extension using std::filesystem
    std::string fileExtension = fs::path(filename).extension().string();

    // Generate a random name using the safe characters (Not exhaustive)
    const std::string safeChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    std::uniform_int_distribution<std::size_t> dist(0, safeChars.size() - 1);

    fs::path path(filename);
    std::error_code ec;

    // (Try to) rename the file numTimes times
    for (int i = 0; i < numTimes; ++i) {
        if (i >= maxTries) break;   // Give up after 10 tries
        fs::path tmpPath = path;    // Track renaming

        // Generate a random number of characters for the new name
        int numChars = numDist(gen);

        std::string newName;
        // Generate a random name
        for (int j = 0; j < numChars; ++j)
            newName += safeChars[dist(gen)];
        newName += fileExtension; // preserve the file extension
        path.replace_filename(newName);

        // Rename the file if it doesn't exist to avoid overwriting existing files
        if (!fs::exists(path)) {
            fs::rename(tmpPath, path, ec);
            // Try again if there was an error
            if (ec) {
                ++numTimes;
                ec.clear();
            }

        } else ++numTimes; // Try again, the file already exists
    }

    fs::remove(path, ec);
    if (ec) std::cerr << "Failed to delete " << filename << ": " << ec.message() << '\n';
}

/**
 * @brief wipes the cluster tips of a file.
 * @param fileName the path to the file to be wiped.
 */
inline void wipeClusterTips(const std::string &fileName) {
    int fileDescriptor = open(fileName.c_str(), O_RDWR);
    if (fileDescriptor == -1) {
        perror("Failed to open file to wipe cluster tips:");
        return;
    }
    // Get the file stats
    struct stat fileStat{};
    if (fstat(fileDescriptor, &fileStat) == -1) {
        perror("Failed to get file size:");
        close(fileDescriptor);
        return;
    }
    // Get the block size of the filesystem
    const auto blockSize = fileStat.st_blksize;
    if (blockSize == 0) {
        std::cerr << "Invalid block size for the filesystem." << std::endl;
        close(fileDescriptor);
        return;
    }
    // Calculate the size of the cluster tip
    auto clusterTipSize = blockSize - (fileStat.st_size % blockSize);

    // If the cluster tip size is larger than the file size, set it to 0
    if (clusterTipSize >= fileStat.st_size)
        clusterTipSize = 0;

    // Write zeros to the cluster tip
    if (clusterTipSize > 0) {
        off_t offset = lseek(fileDescriptor, 0, SEEK_END);
        if (offset == -1) {
            perror("Failed to seek to end of file:");
            close(fileDescriptor);
            return;
        }
        std::vector<char> zeroBuffer(clusterTipSize, 0);
        std::size_t bytesWritten = write(fileDescriptor, zeroBuffer.data(), zeroBuffer.size());
        if (bytesWritten == static_cast<std::size_t>(-1)) {
            perror("Failed to write zeros:");
            close(fileDescriptor);
            return;
        }
    }

    close(fileDescriptor);
}

/**
 * @brief shreds a file by overwriting it with random bytes
 * @param filename path to the file being overwritten
 */
void simpleShred(const std::string &filename, const int &nPasses = 3, bool wipeClusterTip = false) {
    std::ofstream file(filename, std::ios::binary | std::ios::in);
    if (!file)
        throw std::runtime_error("\nFailed to open file: " + filename);

    // Get the file size
    file.seekp(0, std::ios::end);
    std::streamoff fileSize = file.tellp();
    file.seekp(0, std::ios::beg);

    // Shred the file
    overwriteRandom(file, fileSize, nPasses);

    file.close();
    if (wipeClusterTip) wipeClusterTips(filename);

    // Rename and remove the file
    renameAndRemove(filename, 3);
}

/**
 * @brief shreds a file using a simple version of
 * The U.S Department of Defence (DoD) 5220.22-M Standard algorithm.
 * @param filename - the path to the file to be shred.
 */
void dod5220Shred(const std::string &filename, const int &nPasses = 3, bool wipeClusterTip = false) {
    std::ofstream file(filename, std::ios::binary | std::ios::in);
    if (!file)
        throw std::runtime_error("\nFailed to open file: " + filename);

    // Get the file size
    file.seekp(0, std::ios::end);
    std::streamoff fileSize = file.tellp();
    file.seekp(0, std::ios::beg);

    // The DoD 5220.22-M Standard algorithm (I'm avoiding recursion, hence the lambda)
    auto dod3Pass = [&file, &fileSize] -> void {
        unsigned char zeroByte = 0x00;
        unsigned char oneByte = 0xFF;
        // Pass 1: Overwrite with zeros
        overwriteConstantByte(file, zeroByte, fileSize);

        // Pass 2: Overwrite with ones
        overwriteConstantByte(file, oneByte, fileSize);

        // Pass 3: Overwrite with random data
        overwriteRandom(file, fileSize);
        file.close();
    };

    if (nPasses == 3) {
        dod3Pass();
    } else if (nPasses == 7) {
        dod3Pass();
        overwriteRandom(file, fileSize);
        dod3Pass();
    } else throw std::runtime_error("\nInvalid number of passes: " + std::to_string(nPasses));

    if (file.is_open()) file.close();
    if (wipeClusterTip) wipeClusterTips(filename);

    // Rename and remove the file
    renameAndRemove(filename, 3);
}

/**
 * @brief Represents the different shredding options.
 */
enum class shredOptions : const
unsigned int {
    Simple          = 1 << 0,   // Simple overwrite with random bytes
    Dod5220         = 1 << 1,   // DoD 5220.22-M Standard algorithm
    Dod5220_7       = 1 << 2,   // DoD 5220.22-M Standard algorithm with 7 passes
    WipeClusterTips = 1 << 3    // Wiping of the cluster tips
};

/**
 * @brief Adds write and write permissions to a file, if the user has authority.
 * @param fileName The file to modify.
 * @return True if the operation succeeds, else false.
 *
 * @details The actions of this function are similar to the unix command:
 * @code chmod ugo+rw fileName @endcode or @code chmod a+rw fileName @endcode
 * The read/write permissions are added for everyone.
 *
 * @note This function is meant for the file shredder ONLY, which might
 * need to modify a file's permissions (if and only if it has to) to successfully shred it.
 *
 * @warning Modifying file permissions unnecessarily is a serious security risk,
 * and this program doesn't take that for granted.
 */
inline bool addReadWritePermissions(const std::string &fileName) noexcept {
    std::error_code ec;
    fs::permissions(fileName, fs::perms::owner_read | fs::perms::owner_write | fs::perms::group_read |
                              fs::perms::group_write | fs::perms::others_read | fs::perms::others_write,
                    fs::perm_options::add, ec);
    return !ec;
}

/**
 * @brief shreds a file (or all files and subdirectories of a directory)
 * using the specified options.
 * @param filePath - the path to the file to be shred.
 * @param options - the options to use when shredding the file.
 * @param simplePasses - the number of passes for random overwrite
 * for simple shredding.
 * @return true if the file (or directory) was shred successfully, false otherwise.
 * @warning If the filePath is a directory, then all its files and subdirectories
 * are shredded without warning.
 */
bool shredFiles(const std::string &filePath, const unsigned int &options, const int &simplePasses = 3) {
    std::error_code ec;
    fs::file_status fileStatus = fs::status(filePath, ec);
    if (ec) {
        std::cerr << "Failed to determine " << filePath << "'s status: " << ec.message() << std::endl;
        return false;
    }
    // Check if the file exists and is a regular file.
    if (!fs::exists(fileStatus)) {
        std::cerr << "File does not exist: " << filePath << std::endl;
        return false;
    }// If the filepath is a directory, shred all the files in the directory and all its subdirectories
    else if (fs::is_directory(fileStatus)) {
        if (fs::is_empty(filePath, ec)) {
            if (ec) ec.clear();
            else {
                std::cout << "The path is an empty directory." << std::endl;
                return true;
            }
        }
        static std::size_t numShredded{0}, numNotShredded{0};

        // Shred all files in the directory and all subdirectories
        for (const auto &entry: fs::recursive_directory_iterator(filePath)) {
            if (fs::exists(entry.status())) {
                if (!fs::is_directory(entry.status())) {
                    std::cout << "Shredding " << entry.path() << "..";
                    try {
                        bool shredded = shredFiles(entry.path(), options);
                        std::cout << (shredded ? "\tshredded successfully." : "\tshredding failed.") << std::endl;

                        ++(shredded ? numShredded : numNotShredded);

                    } catch (std::runtime_error &err) {
                        std::cerr << err.what() << std::endl;
                        std::cerr << "shredding failed." << std::endl;
                    }
                }
            }
        }
        fs::remove_all(filePath);

        std::cout << "\nProcessed " << numShredded + numNotShredded << " files." << std::endl;
        if (numShredded) std::cout << "Successfully shredded and deleted: " << numShredded << std::endl;
        if (numNotShredded) std::cerr << "Failed to shred " << numNotShredded << " files." << std::endl;

        return true;
    } else if (!fs::is_regular_file(fileStatus)) {
        std::cerr << "'" << filePath << "' is not a regular file." << std::endl;
        std::cout << "Do you want to (try to) shred the file anyway? (y/n):" << std::endl;

        if (!validateYesNo()) return false;
    }

    // Check file permissions
    if (!isWritable(filePath) || !isReadable(filePath)) {
        if (!addReadWritePermissions(filePath)) {
            std::cerr << "\nInsufficient permissions to shred file: " << filePath << std::endl;
            return false;
        }
    }
    // shred the file according to the options
    if (options & static_cast<unsigned int>(shredOptions::Simple))
        simpleShred(filePath, simplePasses, options & static_cast<unsigned int>(shredOptions::WipeClusterTips));
    else if (options & static_cast<unsigned int>(shredOptions::Dod5220))
        dod5220Shred(filePath, 3, options & static_cast<unsigned int>(shredOptions::WipeClusterTips));
    else if (options & static_cast<unsigned int>(shredOptions::Dod5220_7))
        dod5220Shred(filePath, 7, options & static_cast<unsigned int>(shredOptions::WipeClusterTips));
    else throw std::runtime_error("Invalid shred options.");

    return true;
}

void fileShredder() {
    /** @brief Configures the shredding options. */
    auto selectPreferences = [](unsigned int &preferences, int &simpleNumPass) {
        int moreChoices1 = getResponseInt("\n1. Continue with default shredding options\n"
                                          "2. Configure shredding options");
        unsigned const int &wipeTips = static_cast<unsigned int>(shredOptions::WipeClusterTips);

        if (moreChoices1 == 1) {
            preferences |= static_cast<unsigned int>(shredOptions::Simple) | wipeTips;
        } else if (moreChoices1 == 2) {
            int alg = getResponseInt("\nChoose a shredding algorithm:\n"
                                     "1. Overwrite with random bytes (default)\n"
                                     "2. 3-pass DoD 5220.22-M Standard algorithm\n"
                                     "3. 7-pass DoD 5220.22-M Standard algorithm");
            if (alg == 1) {
                preferences |= static_cast<unsigned int>(shredOptions::Simple) | wipeTips;
                int simpleConfig{0};

                do {
                    simpleConfig = getResponseInt("\n1. Continue\n"
                                                  "2. Change the number of passes (default is 3)\n"
                                                  "3. Configure wiping of cluster tips (enabled by default)\n"
                                                  "4. Abort");
                    if (simpleConfig == 1) {
                        break;
                    } else if (simpleConfig == 2) {
                        simpleNumPass = getResponseInt(
                                "How many times would you like to overwrite? (3 times is recommended.)");

                        if (simpleNumPass > 10)
                            throw std::length_error("Too many passes.");
                        else if (simpleNumPass < 1) throw std::length_error("Number of passes should be at least 1.");

                    } else if (simpleConfig == 3) {
                        preferences = (preferences & ~wipeTips) |
                                      (-validateYesNo("Wipe cluster tips? (Recommended) (y/n):") & wipeTips);
                    } else if (simpleConfig == 4) {
                        throw std::runtime_error("Operation aborted.");
                    } else {
                        std::cerr << "Invalid option." << std::endl;
                        continue;
                    }
                } while (true);

            } else if (alg == 2 || alg == 3) {
                preferences |= static_cast<unsigned int>(alg == 2 ? shredOptions::Dod5220 : shredOptions::Dod5220_7);

                preferences = (preferences & ~wipeTips) |
                              (-validateYesNo("Wipe cluster tips? (Recommended) (y/n):") & wipeTips);

            } else throw std::invalid_argument("Invalid option");

        } else throw std::invalid_argument("Invalid option");
    };

    while (true) {
        std::cout << "\n------------------ file shredder ------------------" << std::endl;
        std::cout << "1. Shred a file" << std::endl;
        std::cout << "2. Shred a directory" << std::endl;
        std::cout << "3. Exit" << std::endl;
        std::cout << "---------------------------------------------------" << std::endl;

        int choice = getResponseInt("Enter your choice: ");

        if (choice == 1 || choice == 2) {
            try {
                std::string path = getResponseStr(std::format("Enter the path to the {} you would like to shred:",
                                                              choice == 1 ? "file" : "directory"));

                if (auto len = path.size(); len > 1 && (path.ends_with('/') || path.ends_with('\\')))
                    path.erase(len - 1);

                std::error_code ec;
                fs::file_status fileStatus = fs::status(path, ec);
                if (ec) {
                    std::cerr << ec.message() << std::endl;
                    ec.clear();
                    continue;
                }
                bool isDir{fs::is_directory(fileStatus)};

                if (!fs::exists(fileStatus)) {
                    std::cerr << "'" << path << "' does not exist." << std::endl;
                    continue;
                } else if (choice == 1 && isDir) {
                    std::cout << "'" << path << "' is a directory.\n";
                    std::cout << "Shred all files in '" << path << "' and all its subdirectories? (y/n):" << std::endl;
                    if (!validateYesNo()) continue;
                } else if (choice == 2 && !isDir) {
                    std::cout << "'" << path << "' is not a directory.\n";
                    if (!validateYesNo("Shred it anyway? (y/n):")) continue;
                }
                unsigned int preferences{0};
                int simpleNumPass{3};
                try {
                    selectPreferences(preferences, simpleNumPass);
                } catch (const std::exception &ex) {
                    std::cerr << "Error: " << ex.what() << std::endl;
                    continue;
                }

                std::cout << "\nPreferences:\n";

                if (preferences & static_cast<unsigned int>(shredOptions::Simple))
                    std::cout << "Simple with " << simpleNumPass << " passes." << std::endl;
                if (preferences & static_cast<unsigned int>(shredOptions::Dod5220))
                    std::cout << "3-pass DoD"<< std::endl;
                if (preferences & static_cast<unsigned int>(shredOptions::Dod5220_7))
                    std::cout << "7-pass DoD"<< std::endl;
                if (preferences & static_cast<unsigned int>(shredOptions::WipeClusterTips))
                    std::cout << "Wipe cluster tips too"<< std::endl;

                std::cout << std::endl;

                if (validateYesNo(std::format("The {} contents will be lost permanently. Continue? (y/n)",
                                              isDir ? "directory's (and all its subdirectories')" : "file"))) {

                    std::cout << "Shredding '" << path << "'..." << std::endl;
                    bool shredded = shredFiles(path, preferences, simpleNumPass);
                    if (!isDir)
                        std::cout << (shredded ? "Successfully shredded " : "Failed to shred ") << path << std::endl;
                }
            } catch (const std::exception &err) {
                std::cerr << "Error: " << err.what() << std::endl;
                continue;
            }

        } else if (choice == 3) break;
        else {
            std::cerr << "Invalid choice." << std::endl;
        }
    }
}
