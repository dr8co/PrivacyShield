#include <iostream>
#include <termios.h>
#include <unistd.h>

/**
 * @brief reads sensitive input from a terminal without echoing them.
 * @return a string of the information read.
 */
std::string getSensitiveInfo() {
    std::string password;
    termios oldSettings, newSettings;

    // Turn off terminal echoing
    tcgetattr(STDIN_FILENO, &oldSettings);
    newSettings = oldSettings;
    newSettings.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newSettings);

    // Read password from input
    std::getline(std::cin, password);

    // Restore terminal settings
    tcsetattr(STDIN_FILENO, TCSANOW, &oldSettings);
    std::cout << std::endl;

    return password;
}
