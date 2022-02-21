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
