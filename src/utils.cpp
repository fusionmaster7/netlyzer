#include "./headers/utils.h"

std::string ConvertToHexadecimal(uint8_t* buf, int buf_len) {
    /* String stream for hex conversion and parsing */
    std::stringstream ss;

    for (int i = 0; i < buf_len; i++) {
        uint val = (u_char) * (buf + i);
        ss << std::setw(2) << std::setfill('0') << std::hex << val;
        if (i < buf_len - 1) {
            ss << ":";
        }
    }

    return ss.str();
}

int GetTerminalWidth() {
    winsize w;
    ioctl(STDOUT_FILENO, TIOCGWINSZ, &w);
    return w.ws_col;
}

void PrintSeperator(char sep, int count) {
    for (int i = 0; i < count; i++) {
        std::cout << sep;
    }

    std::cout << "\n";
}

int BtoHex2(uint16_t val) {
    /* Create a stringstream to write to */
    std::stringstream ss;

    /* Extract the bytes */
    int second_byte = (val & 0xFF);
    int first_byte = (val >> 8) & 0xFF;

    /* Write the bytes to the string stream */
    ss << std::setw(2) << std::setfill('0') << second_byte;
    ss << std::setw(2) << std::setfill('0') << first_byte;

    /* Convert string to integer using base 16 */
    return std::stoi(ss.str(), 0, 16);
}