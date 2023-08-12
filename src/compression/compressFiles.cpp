#include <iostream>
#include <fstream>
#include <vector>
#include <bzlib.h>

constexpr int BufferSize = 8192;  // Read files in chunks of 8 KB

/**
 * Function to compress a file using Bzip2.
 * @param inputFile Path to input file.
 * @param compressedFile Path to save the compressed file.
 * @return True if compression was successful, false otherwise.
 */
bool compressFile(const std::string &inputFile, const std::string &compressedFile) {
    // Open input file in binary mode
    std::ifstream inFile(inputFile, std::ios::binary);
    if (!inFile) {
        std::cerr << "Failed to open input file: " << inputFile << std::endl;
        return false;
    }

    // Open compressed file in binary mode
    std::ofstream outFile(compressedFile, std::ios::binary);
    if (!outFile) {
        std::cerr << "Failed to open the destination file: " << compressedFile << std::endl;
        inFile.close();
        return false;
    }

    // Set up Bzip2 stream for compression
    bz_stream bzipStream{};
    bzipStream.bzalloc = nullptr;
    bzipStream.bzfree = nullptr;
    bzipStream.opaque = nullptr;

    // Initialize Bzip2 compression
    int result = BZ2_bzCompressInit(&bzipStream, 9, 0, 0);
    if (result != BZ_OK) {
        std::cerr << "Bzip2 compression initialization failed: " << result << std::endl;
        inFile.close();
        outFile.close();
        return false;
    }

    // Read and compress data in chunks
    std::vector<char> inBuffer(BufferSize);
    std::vector<char> outBuffer(BufferSize);

    // Read input file in chunks, compress, and write to output file
    do {
        inFile.read(inBuffer.data(), BufferSize);
        std::streamsize bytesRead = inFile.gcount();
        if (bytesRead > 0) {
            bzipStream.next_in = inBuffer.data();
            bzipStream.avail_in = static_cast<unsigned int>(bytesRead);

            do {
                bzipStream.next_out = outBuffer.data();
                bzipStream.avail_out = BufferSize;

                result = BZ2_bzCompress(&bzipStream, BZ_RUN);
                if (result < 0) {
                    std::cerr << "Bzip2 compression failed: " << result << std::endl;
                    BZ2_bzCompressEnd(&bzipStream);
                    inFile.close();
                    outFile.close();
                    return false;
                }

                std::streamsize bytesWritten = BufferSize - bzipStream.avail_out;
                outFile.write(outBuffer.data(), bytesWritten);
            } while (bzipStream.avail_out == 0);
        }
    } while (inFile);

    // Finish compression
    do {
        bzipStream.next_out = outBuffer.data();
        bzipStream.avail_out = BufferSize;

        result = BZ2_bzCompress(&bzipStream, BZ_FINISH);
        if (result < 0) {
            std::cerr << "Bzip2 compression failed: " << result << std::endl;
            BZ2_bzCompressEnd(&bzipStream);
            inFile.close();
            outFile.close();
            return false;
        }

        std::streamsize bytesWritten = BufferSize - bzipStream.avail_out;
        outFile.write(outBuffer.data(), bytesWritten);
    } while (result != BZ_STREAM_END);

    // Clean up
    BZ2_bzCompressEnd(&bzipStream);
    inFile.close();
    outFile.close();

    return true;
}

/**
 * Function to decompress a file using Bzip2.
 * @param compressedFile Path to the compressed file.
 * @param outputFile Path to save the decompressed file.
 * @return True if decompression was successful, false otherwise.
 */
bool decompressFile(const std::string &compressedFile, const std::string &outputFile) {
    // Open compressed file in binary mode
    std::ifstream inFile(compressedFile, std::ios::binary);
    if (!inFile) {
        std::cerr << "Failed to open compressed file: " << compressedFile << std::endl;
        return false;
    }

    // Open output file in binary mode
    std::ofstream outFile(outputFile, std::ios::binary);
    if (!outFile) {
        std::cerr << "Failed to open output file: " << outputFile << std::endl;
        inFile.close();
        return false;
    }

    // Set up Bzip2 stream for decompression
    bz_stream bzipStream{};
    bzipStream.bzalloc = nullptr;
    bzipStream.bzfree = nullptr;
    bzipStream.opaque = nullptr;

    // Initialize Bzip2 decompression
    int result = BZ2_bzDecompressInit(&bzipStream, 0, 0);
    if (result != BZ_OK) {
        std::cerr << "Bzip2 decompression initialization failed: " << result << std::endl;
        inFile.close();
        outFile.close();
        return false;
    }

    // Read and decompress data in chunks
    std::vector<char> inBuffer(BufferSize);
    std::vector<char> outBuffer(BufferSize);

    // Read input file in chunks, decompress, and write to output file
    do {
        inFile.read(inBuffer.data(), BufferSize);
        std::streamsize bytesRead = inFile.gcount();
        if (bytesRead > 0) {
            bzipStream.next_in = inBuffer.data();
            bzipStream.avail_in = static_cast<unsigned int>(bytesRead);

            do {
                bzipStream.next_out = outBuffer.data();
                bzipStream.avail_out = BufferSize;

                result = BZ2_bzDecompress(&bzipStream);
                if (result != BZ_STREAM_END && result < 0) {
                    std::cerr << "Bzip2 decompression failed: " << result << std::endl;
                    BZ2_bzDecompressEnd(&bzipStream);
                    inFile.close();
                    outFile.close();
                    return false;
                }

                std::streamsize bytesWritten = BufferSize - bzipStream.avail_out;
                outFile.write(outBuffer.data(), bytesWritten);
            } while (bzipStream.avail_out == 0);
        }
    } while (inFile);

    // Clean up
    BZ2_bzDecompressEnd(&bzipStream);
    inFile.close();
    outFile.close();

    return true;
}
