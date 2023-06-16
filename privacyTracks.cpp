#include <filesystem>
#include <iostream>
#include <vector>

namespace fs = std::filesystem;

/**
 * Detects common browsers installed in a system
 * @return a vector of detected browsers
 */
std::vector<std::string> detectBrowsers() {
    std::vector<std::string> browsers;

    // List of common browser executable names
    std::vector<std::string> browserExecutables = {
            "firefox",
            "google-chrome",
            "chromium-browser",
            "opera",
    };

    // Search for each browser executable in the PATH environment variable
    for (const auto &browser: browserExecutables) {
        if (fs::exists(fs::path("/usr/bin/" + browser))) {
            browsers.push_back(browser);
        }
    }

    return browsers;
}
