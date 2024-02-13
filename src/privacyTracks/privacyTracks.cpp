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

#include "privacyTracks.hpp"
#include <format>
#include <iostream>
#include <string>
#include <vector>
#include <filesystem>

import utils;

namespace fs = std::filesystem;


/// \brief Represents different browsers in a system.
enum class Browser : const
unsigned int {
        Firefox  = 1 << 0,
        Chrome   = 1 << 1,
        Chromium = 1 << 2,
        Opera    = 1 << 3,
        Safari   = 1 << 4
};

/// \brief A convenience function for handling errors during file operations.
/// \param ec the error code associated with the error.
/// \param context the context in which the error occurred.
/// \param path the path of the file in which the error occurred.
inline void handleFileError(std::error_code &ec, const std::string &context = "", const std::string &path = "") {
    if (ec) {
        printColor(std::format("Error {} {}: {}", context, path, ec.message()), 'r', true, std::cerr);
        ec.clear();
    }
}

/// \brief Detects browsers installed on the system.
/// \param pathEnv The PATH environment variable.
/// \return A bit mask of detected browsers.
unsigned int detectBrowsers(const std::string &pathEnv) {
    unsigned int detectedBrowsers{0};

    // Check if the passed string is empty
    if (pathEnv.empty()) {
        printColor("PATH environment variable not found.", 'r', true, std::cerr);
        return detectedBrowsers;
    }

    // Split the PATH variable into individual paths
    std::string pathEnvStr = pathEnv;
    std::vector<std::string> paths;
    std::size_t pos;
    while ((pos = pathEnvStr.find(':')) != std::string::npos) {
        paths.emplace_back(pathEnvStr.substr(0, pos));
        pathEnvStr.erase(0, pos + 1);
    }
    paths.emplace_back(pathEnvStr);

    // Find the list of programs in each path
    std::error_code ec;
    for (const std::string &path: paths) {
        if (!fs::exists(path, ec)) {
            handleFileError(ec, "reading", path);
            continue;
        }
        // Iterate over each entry in the directory and detect browsers
        for (const auto &entry: fs::directory_iterator(path, fs::directory_options::skip_permission_denied |
                                                             fs::directory_options::follow_directory_symlink, ec)) {
            // Handle errors while reading the directory
            handleFileError(ec, "reading", entry.path());

            // Skip broken symlinks
            if (fs::exists(entry.status())) {
                // Check for the existence of the browser executable
                if (auto executable = entry.path().filename().string(); !entry.is_directory() && entry.exists()) {
                    if (executable == "firefox")
                        detectedBrowsers |= static_cast<unsigned int>(Browser::Firefox);
                    else if (executable == "google-chrome")
                        detectedBrowsers |= static_cast<unsigned int>(Browser::Chrome);
                    else if (executable == "chromium-browser")
                        detectedBrowsers |= static_cast<unsigned int>(Browser::Chromium);
                    else if (executable == "opera")
                        detectedBrowsers |= static_cast<unsigned int>(Browser::Opera);
                    else if (executable == "safari")
                        detectedBrowsers |= static_cast<unsigned int>(Browser::Safari);
                }
            }
        }
    }
    return detectedBrowsers;
}

/// \brief Detects browsers installed on the system.
/// \return A bit mask of detected browsers.
/// \details This function uses the PATH environment variable to detect browsers.
/// \note Only stable versions of browsers are detected.
unsigned int detectBrowsers() {
    if (auto pathEnv = getEnv("PATH"); pathEnv)
        return detectBrowsers(*pathEnv);
    else {
        printColor("PATH environment variable not found.", 'r', true, std::cerr);
        return 0;
    }
}

/// \brief Clears Firefox cookies and history.
/// \param configDir The path to the Firefox config directory.
/// \return true if successful, false otherwise.
bool clearFirefoxTracks(const std::string &configDir) {
    if (!fs::exists(configDir)) {
        printColor("Firefox config directory not found.", 'r', true, std::cerr);
        return false;
    }

    std::error_code ec;

    // Find all default profiles
    std::vector<fs::path> defaultProfileDirs;
    for (const auto &entry: fs::directory_iterator(configDir, fs::directory_options::skip_permission_denied |
                                                              fs::directory_options::follow_directory_symlink, ec)) {
        handleFileError(ec, "reading", configDir);
        if (fs::exists(entry.status())) {  // skip broken symlinks
            if (entry.is_directory() && entry.path().filename().string().contains(".default"))
                defaultProfileDirs.emplace_back(entry.path());
        }
    }

    // Clear cookies and history for default profiles
    if (!defaultProfileDirs.empty()) {
        std::cout << "Deleting cookies and history for the following default profiles:" << std::endl;
        for (const auto &profile: defaultProfileDirs) {
            printColor(profile.filename().string(), 'c', true);
            // Clearing cookies
            fs::remove(profile / "cookies.sqlite", ec);
            handleFileError(ec, "deleting", profile / "cookies.sqlite");

            // Clearing history
            fs::remove(profile / "places.sqlite", ec);
            handleFileError(ec, "deleting", profile / "places.sqlite");

        }
    } else printColor("No default profiles found.", 'r', true);

    // Treat the other directories as profiles
    std::vector<fs::path> profileDirs;
    for (const auto &entry: fs::directory_iterator(configDir, fs::directory_options::skip_permission_denied |
                                                              fs::directory_options::follow_directory_symlink, ec)) {
        handleFileError(ec, "reading", configDir);
        if (fs::exists(entry.status())) { // skip broken symlinks
            if (entry.is_directory() && !entry.path().filename().string().contains(".default") &&
                entry.path().filename().string() != "Crash Reports" &&
                entry.path().filename().string() != "Pending Pings")
                profileDirs.emplace_back(entry.path());
        }
    }
    int nonDefaultProfiles{0};
    bool alreadyCounted{false};

    if (!profileDirs.empty()) {
        // Find all cookies.sqlite files in the profile directories
        std::cout << "\nScanning non-default profiles..." << std::endl;
        for (const auto &profile: profileDirs) {
            for (const auto &entry: fs::directory_iterator(profile, fs::directory_options::skip_permission_denied |
                                                                    fs::directory_options::follow_directory_symlink,
                                                           ec)) {
                handleFileError(ec, "reading", profile);
                if (fs::exists(entry.status())) { // Ignore broken symlinks
                    if (entry.is_regular_file()) {
                        if (entry.path().filename() == "cookies.sqlite") {
                            fs::remove(entry.path(), ec);
                            if (ec)
                                handleFileError(ec, "deleting", entry.path());
                            else {
                                std::cout << "Found ";
                                printColor(profile.filename(), 'c', true);
                                ++nonDefaultProfiles;
                                alreadyCounted = true;
                            }
                        }
                        if (entry.path().filename() == "places.sqlite") {
                            if (!alreadyCounted) {
                                std::cout << "Found ";
                                printColor(profile.filename(), 'c', true);
                                ++nonDefaultProfiles;
                            }
                            fs::remove(entry.path(), ec);
                            handleFileError(ec, "deleting", entry.path());
                        }
                    }
                }
            }
        }
    }
    printColor(nonDefaultProfiles ? std::format("Deleted cookies and history for {} non-default profiles.",
                                                nonDefaultProfiles) : "Non-default profiles not found.",
               nonDefaultProfiles ? 'g' : 'r', true);

    return true;
}

/// \brief Clears Chromium and Chrome cookies and history.
/// \param configDir the Chromium or Chrome config directory.
/// \return true if successful, false otherwise.
bool clearChromiumTracks(const std::string &configDir) {
    if (!fs::exists(configDir)) {
        printColor("Config directory not found.", 'r', true, std::cerr);
        return false;
    }

    std::error_code ec;

    // Find the "Default" or "default" profile directory
    fs::path defaultProfileDir;
    for (const auto &entry: fs::directory_iterator(configDir, fs::directory_options::skip_permission_denied |
                                                              fs::directory_options::follow_directory_symlink, ec)) {
        handleFileError(ec, "reading", configDir);
        if (fs::exists(entry.status())) {
            if (entry.is_directory() &&
                (entry.path().filename() == "Default" || entry.path().filename() == "default")) {
                defaultProfileDir = entry.path();
                break;
            }
        }
    }

    // Clear cookies and history for the default profile
    if (!defaultProfileDir.string().empty()) {
        std::cout << "Deleting cookies and history for the default profile..." << std::endl;
        // Clearing cookies
        fs::remove(defaultProfileDir / "Cookies", ec);
        handleFileError(ec, "deleting", defaultProfileDir / "Cookies");

        // Clearing history
        fs::remove(defaultProfileDir / "History", ec);
        handleFileError(ec, "deleting", defaultProfileDir / "History");
    } else printColor("Default profile directory not found.", 'r', true, std::cerr);

    // Find other profile directories
    std::vector<fs::path> profileDirs;
    for (const auto &entry: fs::directory_iterator(configDir, fs::directory_options::skip_permission_denied |
                                                              fs::directory_options::follow_directory_symlink, ec)) {
        handleFileError(ec, "reading", configDir);
        if (fs::exists(entry.status())) {

            if (entry.is_directory() && entry.path().filename() != "Default" && entry.path().filename() != "default") {
                profileDirs.emplace_back(entry.path());
            }
        }
    }

    int nonDefaultProfiles{0};
    bool alreadyCounted{false};

    // Find all cookies files in the other profile directories
    if (!profileDirs.empty()) {
        std::cout << "\nScanning non-default profiles..." << std::endl;
        for (const auto &profile: profileDirs) {
            for (const auto &entry: fs::directory_iterator(profile, fs::directory_options::skip_permission_denied |
                                                                    fs::directory_options::follow_directory_symlink,
                                                           ec)) {
                handleFileError(ec, "reading", profile);
                if (fs::exists(entry.status())) { // ignore broken symlinks
                    if (entry.is_regular_file()) {
                        // Clearing cookies
                        if (entry.path().filename() == "Cookies") {
                            fs::remove(entry.path(), ec);
                            if (ec)
                                handleFileError(ec, "deleting", entry.path());
                            else {
                                std::cout << "Found ";
                                printColor(profile.filename(), 'c', true);
                                ++nonDefaultProfiles;
                                alreadyCounted = true;
                            }
                        }
                        // Clearing history
                        if (entry.path().filename() == "History") {
                            if (!alreadyCounted) {
                                std::cout << "Found ";
                                printColor(profile.filename(), 'c', true);
                                ++nonDefaultProfiles;
                            }
                            fs::remove(entry.path(), ec);
                            handleFileError(ec, "deleting", entry.path());
                        }
                    }
                }
            }
        }
    }
    printColor(nonDefaultProfiles ? std::format("Deleted cookies and history for {} non-default profiles.",
                                                nonDefaultProfiles) : "Non-default profiles not found.",
               nonDefaultProfiles ? 'g' : 'r', true);

    return true;
}

/// \brief Clears Opera cookies and history.
/// \param profilePath the Opera profile directory.
/// \return true if successful, false otherwise.
bool clearOperaTracks(const std::string &profilePath) {
    bool ret{true};

    // Check if the Opera config directory exists
    if (!fs::exists(profilePath)) {
        printColor("Opera config directory not found.", 'r', true, std::cerr);
        return false;
    }

    std::error_code ec;

    // Clear cookies
    fs::remove(profilePath + "/Cookies", ec);
    if (ec) {
        ec.clear();
        fs::remove(profilePath + "/cookies", ec);
        if (ec) {
            handleFileError(ec, "deleting", profilePath + "/cookies");
            ec.clear();
            ret = false;  // We don't to return yet, we want to try to clear history too
        }
    }

    // Clear history
    fs::remove(profilePath + "/History", ec);
    if (ec) {
        ec.clear();
        fs::remove(profilePath + "/history", ec);
        if (ec) {
            handleFileError(ec, "deleting", profilePath + "/history");
            ec.clear();
            return false; // No point in continuing
        }
    }

    return ret;
}

/// \brief Clears Opera cookies and history.
/// \return true if successful, false otherwise.
bool clearChromiumTracks() {
#if __linux__ or __linux
    return clearChromiumTracks(getHomeDir() + "/.config/chromium");
#elif __APPLE__
    return clearChromiumTracks(getHomeDir() + "/Library/Application Support/Chromium");
#else
    printColor("This OS is not supported at the moment.", 'r', true, std::cerr);
    return false;
#endif
}

/// \brief Clears Google Chrome cookies and history.
/// \return true if successful, false otherwise.
bool clearChromeTracks() {
#if __linux__ or __linux
    return clearChromiumTracks(getHomeDir() + "/.config/google-chrome");
#elif __APPLE__
    return clearChromiumTracks(getHomeDir() + "/Library/Application Support/Google/Chrome");
#else
    printColor("This OS is not supported at the moment.", 'r', true, std::cerr);
    return false;
#endif
}

/// \brief Clears Opera cookies and history.
/// \return true if successful, false otherwise.
bool clearOperaTracks() {
#if __linux__ or __linux
    return clearOperaTracks(getHomeDir() + "/.config/opera");
#elif __APPLE__
    return clearOperaTracks(getHomeDir() + "/Library/Application Support/com.operasoftware.Opera");
#else
    printColor("This OS is not supported at the moment.", 'r', true, std::cerr);
    return false;
#endif
}

/// \brief Clears Safari cookies and history.
/// \return true if successful, false otherwise.
bool clearSafariTracks() {
#if __APPLE__
    std::string cookiesPath = getHomeDir() + "/Library/Cookies";
    if (!fs::exists(cookiesPath)) {
        printColor("Safari cookies directory not found.", 'r', true, std::cerr);
        return false;
    }

    // clear cookies
    std::error_code ec;
    for (const auto &entry: fs::directory_iterator(cookiesPath, fs::directory_options::skip_permission_denied, ec)) {
        handleFileError(ec, "reading", cookiesPath);
        if (entry.is_regular_file() && entry.path().filename() == "Cookies.binarycookies") {
            fs::remove(entry.path(), ec);
            handleFileError(ec, "deleting", entry.path());
        }
    }

    std::string historyPath = getHomeDir() + "/Library/Safari";
    if (!fs::exists(historyPath)) {
        printColor("Safari history directory not found.", 'r', true, std::cerr);
        return false;
    }

    // clear history
    for (const auto &entry: fs::directory_iterator(historyPath, fs::directory_options::skip_permission_denied, ec)) {
        handleFileError(ec, "reading", historyPath);
        if (entry.is_regular_file() && entry.path().filename() == "History.db") {
            fs::remove(entry.path(), ec);
            if (ec) {
                handleFileError(ec, "deleting", entry.path());
                return false;
            }
        }
    }

    return true;
#else
    printColor("Safari is only available on macOS.", 'r', true, std::cerr);
    return false;
#endif
}

/// \brief Clears Firefox cookies and history.
/// \return true if successful, false otherwise.
bool clearFirefoxTracks() {
#if __linux__ or __linux
    return clearFirefoxTracks(getHomeDir() + "/.mozilla/firefox");
#elif __APPLE__
    return clearFirefoxTracks(getHomeDir() + "/Library/Application Support/Firefox");
#else
    printColor("This OS is not supported at the moment.", 'r', true, std::cerr);
    return false;
#endif
}

/// \brief Clears all tracks for the specified browsers.
/// \param browsers the browsers to clear tracks for.
/// \return true if successful, false otherwise.
/// \note Only works for standard installations of the browsers.
bool clearTracks(unsigned int browsers) {
    bool ret{true};

    if (browsers & static_cast<unsigned int>(Browser::Firefox)) {
        std::cout << "\nClearing Firefox tracks..." << std::endl;
        ret = clearFirefoxTracks();
        printColor(ret ? "Firefox tracks cleared successfully." : "Failed to clear Firefox tracks.", ret ? 'g' : 'r',
                   true, ret ? std::cout : std::cerr);
    }

    if (browsers & static_cast<unsigned int>(Browser::Chrome)) {
        std::cout << "\nClearing Chrome tracks..." << std::endl;
        ret = clearChromeTracks();
        printColor(ret ? "Chrome tracks cleared successfully." : "Failed to clear Chrome tracks.", ret ? 'g' : 'r',
                   true, ret ? std::cout : std::cerr);
    }

    if (browsers & static_cast<unsigned int>(Browser::Chromium)) {
        std::cout << "\nClearing Chromium tracks..." << std::endl;
        ret = clearChromiumTracks();
        printColor(ret ? "Chromium tracks cleared successfully." : "Failed to clear Chromium tracks.", ret ? 'g' : 'r',
                   true, ret ? std::cout : std::cerr);
    }

    if (browsers & static_cast<unsigned int>(Browser::Opera)) {
        std::cout << "\nClearing Opera tracks..." << std::endl;
        ret = clearOperaTracks();
        printColor(ret ? "Opera tracks cleared successfully." : "Failed to clear Opera tracks.", ret ? 'g' : 'r', true,
                   ret ? std::cout : std::cerr);
    }

    if (browsers & static_cast<unsigned int>(Browser::Safari)) {
#if __APPLE__
        std::cout << "Clearing Safari tracks..." << std::endl;
        ret = clearSafariTracks();
        printColor(ret ? "Safari tracks cleared successfully." : "Failed to clear Safari tracks.", ret ? 'g' : 'r',
                   true, ret ? std::cout : std::cerr);
#else
        printColor("\nSafari is only available on macOS.", 'r', true, std::cerr);
        ret = false;
#endif
    }

    return ret;
}

/// \brief Clears all tracks for all supported browsers installed on the system.
/// \note Only works for standard installations of the browsers.
void clearPrivacyTracks() {
    std::cout << "Scanning your system for browsers..." << std::endl;

    unsigned int browsers = detectBrowsers();
    if (browsers == 0) {
        printColor("No supported browsers found.", 'r', true, std::cerr);
        return;
    } else [[likely]] {
        printColor("Supported browsers found:", 'b', true);
        if (browsers & static_cast<unsigned int>(Browser::Firefox))
            printColor("Firefox", 'c', true);

        if (browsers & static_cast<unsigned int>(Browser::Chrome))
            printColor("Chrome", 'c', true);

        if (browsers & static_cast<unsigned int>(Browser::Chromium))
            printColor("Chromium", 'c', true);

        if (browsers & static_cast<unsigned int>(Browser::Opera))
            printColor("Opera", 'c', true);

        if (browsers & static_cast<unsigned int>(Browser::Safari))
            printColor("Safari", 'c', true);
    }
    printColor("\nAll the cookies and browsing history of the above browsers will be deleted.", 'r', true);
    printColor("Continue? (y/n): ", 'c');

    if (validateYesNo()) {
        auto cleared{clearTracks(browsers)};
        printColor(cleared ? "\nAll tracks cleared successfully." : "\nFailed to clear all tracks.",
                   cleared ? 'g' : 'r', true, cleared ? std::cout : std::cerr);

    } else printColor("Aborted.", 'r', true);
}
