#include <iostream>
#include <fstream>
#include <random>
#include <filesystem>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

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
void overwriteConstantByte(std::ofstream &file, T byte, const auto &fileSize) {
    for (std::streamoff pos = 0; pos < fileSize; ++pos) {
        file.write(reinterpret_cast<char *>(&byte), sizeof(T));
    }
}

/**
 * @brief renames a file to a random name.
 * @param filename the path to the file to be renamed.
 * @param numTimes the number of times to rename the file.
 */
inline void renameFile(const std::string &filename, int numTimes = 1) {
    constexpr int maxTries = 10;        // max number of trials to rename the file
    constexpr int minNameLength = 3;    // min length of the random name
    constexpr int maxNameLength = 16;   // max length of the random name

    // Check if the number of times is valid
    if (numTimes < 1) return;
    else if (numTimes > maxTries) numTimes = maxTries;

    // Create a random device for generating secure random numbers
    std::random_device rd;

    // Mersenne Twister engine seeded with rd
    std::mt19937 gen(rd());

    // Distribution for the number of characters in the new name
    std::uniform_int_distribution<int> numDist(minNameLength, maxNameLength);

    // Get the file extension using std::filesystem
    std::string fileExtension = fs::path(filename).extension().string();

    // Generate a random name using the safe characters (Not exhaustive)
    const std::string safeChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    std::uniform_int_distribution<size_t> dist(0, safeChars.size() - 1);

    fs::path path(filename);
    std::error_code ec;

    // (Try to) rename the file numTimes times
    for (int i = 0; i < numTimes; ++i) {
        if (i >= maxTries) return; // Give up after 10 tries

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
            fs::rename(filename, path, ec);
            // Try again if there was an error
            if (ec) {
                ++numTimes;
                ec.clear();
            }

        } else ++numTimes; // Try again, the file already exists
    }
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
        ssize_t bytesWritten = write(fileDescriptor, zeroBuffer.data(), zeroBuffer.size());
        if (bytesWritten == -1) {
            perror("Failed to write zeros:");
            close(fileDescriptor);
            return;
        }

        std::cout << "Cluster tip wiped successfully." << std::endl;
    } else std::cout << "No cluster tip to wipe." << std::endl;

    close(fileDescriptor);
}

/**
 * @brief shreds a file by overwriting it with random bytes
 * @param filename path to the file being overwritten
 */
void simpleShred(const std::string &filename, const int &nPasses = 3, bool wipeClusterTip = false) {
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
    if (wipeClusterTip) wipeClusterTips(filename);
    // Rename the file
    renameFile(filename, 3);
    // Delete the file
    std::error_code ec;
    fs::remove(filename, ec);
    if (ec) std::cerr << "Failed to delete " << filename << ": " << ec.message() << '\n';
}

/**
 * @brief shreds a file using a simple version of
 * The U.S Department of Defence (DoD) 5220.22-M Standard algorithm.
 * @param filename - the path to the file to be shred.
 */
void dod5220Shred(const std::string &filename, const int &nPasses = 3, bool wipeClusterTip = false) {
    std::ofstream file(filename, std::ios::binary | std::ios::in);
    if (!file)
        throw std::runtime_error("Failed to open file: " + filename);

    // Get the file size
    file.seekp(0, std::ios::end);
    std::streamoff fileSize = file.tellp();
    file.seekp(0, std::ios::beg);

    // The DoD 5220.22-M Standard algorithm (I'm avoiding recursion, hence the lambda)
    auto dod3Pass = [&file, &fileSize] -> void {
        uint8_t zeroByte = 0x00;
        uint8_t oneByte = 0xFF;
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
    } else throw std::runtime_error("Invalid number of passes");

    if (file.is_open()) file.close();
    if (wipeClusterTip) wipeClusterTips(filename);

    renameFile(filename, 3);
    // Delete the file
    std::error_code ec;
    fs::remove(filename, ec);
    if (ec) std::cerr << "Failed to delete " << filename << ": " << ec.message() << '\n';
}
