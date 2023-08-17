#pragma once

#include <vector>
#include <string>
#include <cstdint>
#include <optional>
#include <iostream>

template<typename T>
concept PrintableToStream = requires(std::ostream &os, const T &t) {
    os << t;
};

/**
 * @brief Prints colored text to a stream.
 * @param text the text to print.
 * @param color a character representing the desired color.
 * @param printNewLine a flag to indicate whether a newline should be printed after the text.
 * @param os the stream object to print to.
 */
void printColor(const PrintableToStream auto &text, const char &color = 'w', const bool &printNewLine = false,
                std::ostream &os = std::cout) {
    switch (color) {
        case 'r': // Red
            os << "\033[1;31m";
            break;
        case 'g': // Green
            os << "\033[1;32m";
            break;
        case 'y': // Yellow
            os << "\033[1;33m";
            break;
        case 'b': // Blue
            os << "\033[1;34m";
            break;
        case 'm': // Magenta
            os << "\033[1;35m";
            break;
        case 'c': // Cyan
            os << "\033[1;36m";
            break;
        case 'w': // White
            os << "\033[1;37m";
            break;
        default:
            break;
    }
    os << text << "\033[0m";
    if (printNewLine)
        os << std::endl;
}

std::vector<unsigned char> base64Decode(const std::string &encodedData);

std::string base64Encode(const std::vector<unsigned char> &input);

int getResponseInt(const std::string &prompt = "");

std::string getResponseStr(const std::string &prompt = "");

void handleAccessError(const std::string &filename);

bool isWritable(const std::string &filename);

bool isReadable(const std::string &filename);

std::uintmax_t getAvailableSpace(const std::string &path) noexcept;

bool addReadWritePermissions(const std::string &fileName) noexcept;

bool copyFilePermissions(const std::string &srcFile, const std::string &destFile) noexcept;

std::string getSensitiveInfo(const std::string &prompt = "");

bool validateYesNo(const std::string &prompt = "");

//void printColor(const PrintableToStream auto &text, const char &color = 'w', const bool &printNewLine = false, std::ostream &os=std::cout);

std::string getHomeDir() noexcept;

std::optional<std::string> getEnv(const char *var);
