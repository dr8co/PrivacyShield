#include <iostream>
#include <fstream>
#include <random>

void overwriteRandom(const std::string& filename) {
    std::ofstream file(filename, std::ios::binary | std::ios::in);
    if (!file) {
        std::cerr << "Failed to open the file: " << filename << std::endl;
        return;
    }

    // Get the file size
    file.seekp(0, std::ios::end);
    std::streamoff fileSize = file.tellp();
    file.seekp(0, std::ios::beg);

    // Create a random device for generating secure random numbers
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint8_t> dist(0, 255);

    // Overwrite the file with random data
    for (std::streamoff pos = 0; pos < fileSize; ++pos) {
        uint8_t randomByte = dist(gen);
        file.write(reinterpret_cast<char*>(&randomByte), sizeof(uint8_t));
    }

    file.close();
}

template<typename T>
void overwriteConstantByte(std::string& filename, T byte){
    std::ofstream file(filename, std::ios::binary | std::ios::in);
    if (!file) {
        std::cerr << "Failed to open the file: " << filename << std::endl;
        return;
    }

    // Get the file size
    file.seekp(0, std::ios::end);
    std::streamoff fileSize = file.tellp();
    file.seekp(0, std::ios::beg);

    // Overwrite with the byte
    for (std::streamoff pos = 0; pos < fileSize; ++pos) {
        file.write(reinterpret_cast<char*>(&byte), sizeof(T));
    }

    file.close();
}
