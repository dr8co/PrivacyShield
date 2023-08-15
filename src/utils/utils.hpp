#pragma once

#include <vector>
#include <string>
#include <cstdint>
#include <optional>

template<typename T>
concept PrintableToStream = requires(std::ostream &os, const T &t) {
    os << t;
};

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

void printColor(const PrintableToStream auto &text, const char &color = 'w', const bool &printNewLine = false, std::ostream &os=std::cout);

std::string getHomeDir();

std::optional<std::string> getEnv(const char *var);
