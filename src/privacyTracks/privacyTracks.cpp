#include <format>
#include <iostream>
#include <string>
#include <vector>
#include <cstdlib>
#include <filesystem>
#include "privacyTracks.hpp"

namespace fs = std::filesystem;

#if _GNU_SOURCE  // Use secure_getenv() on Linux if available
const char *homeDir = secure_getenv("HOME");
#elif __APPLE__ or __unix or __unix__
const char *homeDir = std::getenv("HOME");
#endif

/**
 * @brief Represents different browsers in a system.
 */
enum class Browser : const
unsigned int {
        Firefox = 1 << 0,
        Chrome = 1 << 1,
        Chromium = 1 << 2,
        Opera = 1 << 3,
        Safari = 1 << 4
};

// TODO: Add support for snap/flatpak-installed browsers on Linux

/**
 * @brief handles errors during file operations.
 * @param ec the error code associated with the error.
 * @param context the context in which the error occurred.
 * @param path the path of the file in which the error occurred.
 */
inline void handleFileError(std::error_code &ec, const std::string &context = "", const std::string &path = "") {
    if (ec) {
        std::cerr << std::format("Error {} {}: {}", context, path, ec.message()) << std::endl;
        ec.clear();
    }
}

/**
 * @brief Detects browsers installed on the system.
 * @param pathEnv The PATH environment variable.
 * @return A bit mask of detected browsers.
 */
unsigned int detectBrowsers(const std::string &pathEnv) {
    unsigned int detectedBrowsers{0};

    // Check if the passed string is empty
    if (pathEnv.empty()) {
        std::cerr << "PATH environment variable not found." << std::endl;
        return detectedBrowsers;
    }

    // Split the PATH variable into individual paths
    std::string pathEnvStr = pathEnv;
    std::vector<std::string> paths;
    size_t pos;
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

            // Check for the existence of the browser executable
            if (!entry.is_directory() && entry.exists()) {
                if (entry.path().filename() == "firefox")
                    detectedBrowsers |= static_cast<unsigned int>(Browser::Firefox);
                else if (entry.path().filename() == "google-chrome")
                    detectedBrowsers |= static_cast<unsigned int>(Browser::Chrome);
                else if (entry.path().filename() == "chromium-browser")
                    detectedBrowsers |= static_cast<unsigned int>(Browser::Chromium);
                else if (entry.path().filename() == "opera")
                    detectedBrowsers |= static_cast<unsigned int>(Browser::Opera);
                else if (entry.path().filename() == "safari")
                    detectedBrowsers |= static_cast<unsigned int>(Browser::Safari);
            }
        }
    }
    return detectedBrowsers;
}

/**
 * @brief Detects browsers installed on the system.
 * @return A bit mask of detected browsers.
 * @details This function uses the PATH environment variable to detect browsers.
 * @note Only stable versions of browsers are detected.
 */
unsigned int detectBrowsers() {
#if _GNU_SOURCE
    const char *pathEnv = secure_getenv("PATH");
    if (pathEnv == nullptr) {
        std::cerr << "PATH environment variable not found." << std::endl;
        return 0;
    }
    return detectBrowsers(std::string(pathEnv));
#elif __APPLE__ or __unix or __unix__
    const char* pathEnv = std::getenv("PATH");
    if (pathEnv == nullptr) {
        std::cerr << "PATH environment variable not found." << std::endl;
        return 0;
    }
    return detectBrowsers(std::string(pathEnv));
#else
    std::cerr << "Unsupported platform." << std::endl;
    return 0;
#endif
}

/**
 * @brief Clears Firefox cookies and history.
 * @param configDir The path to the Firefox config directory.
 * @return true if successful, false otherwise.
 */
bool clearFirefoxTracks(std::string &configDir) {
    if (!fs::exists(configDir)) {
        std::cerr << "Firefox config directory not found." << std::endl;
        return false;
    }

    std::error_code ec;

    // Find all default profiles
    std::vector<fs::path> defaultProfileDirs;
    for (const auto &entry: fs::directory_iterator(configDir, fs::directory_options::skip_permission_denied |
                                                              fs::directory_options::follow_directory_symlink, ec)) {
        handleFileError(ec, "reading", configDir);
        if (entry.is_directory() && entry.path().filename().string().contains(".default"))
            defaultProfileDirs.emplace_back(entry.path());
    }

    // Clear cookies and history for default profiles
    if (!defaultProfileDirs.empty()) {
        std::cout << "Deleting cookies and history for the following default profiles:" << std::endl;
        for (const auto &profile: defaultProfileDirs) {
            std::cout << profile.filename() << std::endl;
            // Clearing cookies
            fs::remove(profile / "cookies.sqlite", ec);
            handleFileError(ec, "deleting", profile / "cookies.sqlite");

            // Clearing history
            fs::remove(profile / "places.sqlite", ec);
            handleFileError(ec, "deleting", profile / "places.sqlite");

        }
    } else std::cout << "No default profiles found." << std::endl;

    // Treat the other directories as profiles
    std::vector<fs::path> profileDirs;
    for (const auto &entry: fs::directory_iterator(configDir, fs::directory_options::skip_permission_denied |
                                                              fs::directory_options::follow_directory_symlink, ec)) {
        handleFileError(ec, "reading", configDir);
        if (entry.is_directory() && !entry.path().filename().string().contains(".default") &&
            entry.path().filename().string() != "Crash Reports" && entry.path().filename().string() != "Pending Pings")
            profileDirs.emplace_back(entry.path());
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
                if (entry.is_regular_file()) {
                    if (entry.path().filename() == "cookies.sqlite") {
                        fs::remove(entry.path(), ec);
                        if (ec)
                            handleFileError(ec, "deleting", entry.path());
                        else {
                            std::cout << "Found " << profile.filename() << std::endl;
                            ++nonDefaultProfiles;
                            alreadyCounted = true;
                        }
                    }
                    if (entry.path().filename() == "places.sqlite") {
                        if (!alreadyCounted) {
                            std::cout << "Found " << profile.filename() << std::endl;
                            ++nonDefaultProfiles;
                        }
                        fs::remove(entry.path(), ec);
                        handleFileError(ec, "deleting", entry.path());
                    }
                }
            }
        }
    }
    std::cout << (nonDefaultProfiles == 0 ? "Non-default profiles not found." : std::format(
            "Deleted cookies and history for {} non-default profiles.", nonDefaultProfiles)) << std::endl;

    return true;
}

/**
 * @brief Clears Chromium and Chrome cookies and history.
 * @param configDir the Chromium or Chrome config directory.
 * @return true if successful, false otherwise.
 */
bool clearChromiumTracks(const std::string &configDir) {
    std::string profilePath = std::string(homeDir) + configDir;
    if (!fs::exists(profilePath)) {
        std::cout << "Profile path: " << profilePath << std::endl;
        std::cerr << "Config directory not found." << std::endl;
        return false;
    }

    std::error_code ec;

    // Find the "Default" or "default" profile directory
    fs::path defaultProfileDir;
    for (const auto &entry: fs::directory_iterator(profilePath, fs::directory_options::skip_permission_denied |
                                                                fs::directory_options::follow_directory_symlink, ec)) {
        handleFileError(ec, "reading", profilePath);
        if (entry.is_directory() && (entry.path().filename() == "Default" || entry.path().filename() == "default")) {
            defaultProfileDir = entry.path();
            break;
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
    } else std::cerr << "Default profile directory not found." << std::endl;

    // Find other profile directories
    std::vector<fs::path> profileDirs;
    for (const auto &entry: fs::directory_iterator(profilePath, fs::directory_options::skip_permission_denied |
                                                                fs::directory_options::follow_directory_symlink, ec)) {
        handleFileError(ec, "reading", profilePath);
        if (entry.is_directory() && entry.path().filename() != "Default" && entry.path().filename() != "default") {
            profileDirs.emplace_back(entry.path());
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
                if (entry.is_regular_file()) {
                    // Clearing cookies
                    if (entry.path().filename() == "Cookies") {
                        fs::remove(entry.path(), ec);
                        if (ec)
                            handleFileError(ec, "deleting", entry.path());
                        else {
                            std::cout << "Found " << profile.filename() << std::endl;
                            ++nonDefaultProfiles;
                            alreadyCounted = true;
                        }
                    }
                    // Clearing history
                    if (entry.path().filename() == "History") {
                        if (!alreadyCounted) {
                            std::cout << "Found " << profile.filename() << std::endl;
                            ++nonDefaultProfiles;
                        }
                        fs::remove(entry.path(), ec);
                        handleFileError(ec, "deleting", entry.path());
                    }
                }
            }
        }
    }
    std::cout << (nonDefaultProfiles == 0 ? "Non-default profiles not found." : std::format(
            "Deleted cookies and history for {} non-default profiles.", nonDefaultProfiles)) << std::endl;

    return true;
}

/**
 * @brief Clears Opera cookies and history.
 * @param profilePath the Opera profile directory.
 * @return true if successful, false otherwise.
 */
bool clearOperaTracks(const std::string &profilePath) {
    bool ret{true};

    // Check if the Opera config directory exists
    if (!fs::exists(profilePath)) {
        std::cerr << "Opera config directory not found." << std::endl;
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
            ret = false;  // we don't to return yet, we want to try to clear history too
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

/**
 * @brief Clears Opera cookies and history.
 * @return true if successful, false otherwise.
 */
bool clearChromiumTracks() {
#if __linux__ or __linux
    std::string configDir = "/.config/chromium";
    return clearChromiumTracks(configDir);
#elif __APPLE__
    std::string configDir = "/Library/Application Support/Chromium";
    return clearChromiumTracks(configDir);
#else
    std::cout << "This OS is not supported at the moment." << std::endl;
    return false;
#endif
}

/**
 * @brief Clears Google Chrome cookies and history.
 * @return true if successful, false otherwise.
 */
bool clearChromeTracks() {
#if __linux__ or __linux
    std::string configDir = "/.config/google-chrome";
    return clearChromiumTracks(configDir);
#elif __APPLE__
    std::string configDir = "/Library/Application Support/Google/Chrome";
    return clearChromiumTracks(configDir);
#else
    std::cout << "This OS is not supported at the moment." << std::endl;
    return false;
#endif
}

/**
 * @brief Clears Opera cookies and history.
 * @return true if successful, false otherwise.
 */
bool clearOperaTracks() {
#if __linux__ or __linux
    std::string profilePath = std::string(homeDir) + "/.config/opera";
    return clearOperaTracks(profilePath);
#elif __APPLE__
    std::string profilePath = std::string(homeDir) + "/Library/Application Support/com.operasoftware.Opera";
    return clearOperaTracks(profilePath);
#else
    std::cout << "This OS is not supported at the moment." << std::endl;
    return false;
#endif
}

/**
 * @brief Clears Safari cookies and history.
 * @return true if successful, false otherwise.
 */
bool clearSafariTracks() {
#if __APPLE__
    std::string cookiesPath = std::string(homeDir) + "/Library/Cookies";
    if (!fs::exists(cookiesPath)) {
        std::cerr << "Safari cookies directory not found." << std::endl;
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

    std::string historyPath = std::string(homeDir) + "/Library/Safari";
    if (!fs::exists(historyPath)) {
        std::cerr << "Safari history directory not found." << std::endl;
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
    std::cerr << "Safari is only available on macOS." << std::endl;
    return false;
#endif
}

/**
 * @brief Clears Firefox cookies and history.
 * @return true if successful, false otherwise.
 */
bool clearFirefoxTracks() {
#if __linux__ or __linux
    std::string profilePath = std::string(homeDir) + "/.mozilla/firefox";
    return clearFirefoxTracks(profilePath);
#elif __APPLE__
    std::string profilePath = std::string(homeDir) + "/Library/Application Support/Firefox";
    return clearFirefoxTracks(profilePath);
#else
    std::cout << "This OS is not supported at the moment." << std::endl;
    return false;
#endif
}

/**
 * @brief Clears all tracks for the specified browsers.
 * @param browsers the browsers to clear tracks for.
 * @return true if successful, false otherwise.
 * @note Only works for standard installations of the browsers.
 */
bool clearTracks(unsigned int browsers) {
    bool ret{true};

    if (browsers & static_cast<unsigned int>(Browser::Firefox)) {
        std::cout << "\nClearing Firefox tracks..." << std::endl;
        ret = clearFirefoxTracks();
        std::cout << (ret ? "Firefox tracks cleared successfully." : "Failed to clear Firefox tracks.") << std::endl;
    }

    if (browsers & static_cast<unsigned int>(Browser::Chrome)) {
        std::cout << "\nClearing Chrome tracks..." << std::endl;
        ret = clearChromeTracks();
        std::cout << (ret ? "Chrome tracks cleared successfully." : "Failed to clear Chrome tracks.") << std::endl;
    }

    if (browsers & static_cast<unsigned int>(Browser::Chromium)) {
        std::cout << "\nClearing Chromium tracks..." << std::endl;
        ret = clearChromiumTracks();
        std::cout << (ret ? "Chromium tracks cleared successfully." : "Failed to clear Chromium tracks.") << std::endl;
    }

    if (browsers & static_cast<unsigned int>(Browser::Opera)) {
        std::cout << "\nClearing Opera tracks..." << std::endl;
        ret = clearOperaTracks();
        std::cout << (ret ? "Opera tracks cleared successfully." : "Failed to clear Opera tracks.") << std::endl;
    }

    if (browsers & static_cast<unsigned int>(Browser::Safari)) {
#if __APPLE__
        std::cout << "Clearing Safari tracks..." << std::endl;
        ret = clearSafariTracks();
        std::cout << (ret ? "Safari tracks cleared successfully." : "Failed to clear Safari tracks.") << std::endl;
#else
        std::cerr << "\nSafari is only available on macOS." << std::endl;
        ret = false;
#endif
    }

    return ret;
}

/**
 * @brief Clears all tracks for all supported browsers installed on the system.
 * @note Only works for standard installations of the browsers.
 */
void clearPrivacyTracks() {
    unsigned int browsers = detectBrowsers();
    if (browsers == 0) {
        std::cout << "No supported browsers found." << std::endl;
        return;
    } else [[likely]] {
        std::cout << "Supported browsers found:" << std::endl;
        if (browsers & static_cast<unsigned int>(Browser::Firefox))
            std::cout << "Firefox" << std::endl;

        if (browsers & static_cast<unsigned int>(Browser::Chrome))
            std::cout << "Chrome" << std::endl;

        if (browsers & static_cast<unsigned int>(Browser::Chromium))
            std::cout << "Chromium" << std::endl;

        if (browsers & static_cast<unsigned int>(Browser::Opera))
            std::cout << "Opera" << std::endl;

        if (browsers & static_cast<unsigned int>(Browser::Safari))
            std::cout << "Safari" << std::endl;
    }
    std::cout << (clearTracks(browsers) ? "\nAll tracks cleared successfully." : "\nFailed to clear all tracks.")
              << std::endl;
}
