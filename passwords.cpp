#include <iostream>
#include <termios.h>
#include <unistd.h>
#include <readline/readline.h>

/**
 * @brief reads sensitive input from a terminal without echoing them.
 * @param prompt the prompt to display.
 * @return a string of the information read.
 */
std::string getSensitiveInfo(const std::string &prompt = "") {
    std::string password;
    char *tmp;
    termios oldSettings{}, newSettings{};

    // Turn off terminal echoing
    tcgetattr(STDIN_FILENO, &oldSettings);
    newSettings = oldSettings;
    newSettings.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newSettings);

    // Read password from input
    tmp = readline(prompt.c_str());
    password = std::string(tmp);
    std::free(tmp);

    // Restore terminal settings
    tcsetattr(STDIN_FILENO, TCSANOW, &oldSettings);
    std::cout << std::endl;

    return password;
}
