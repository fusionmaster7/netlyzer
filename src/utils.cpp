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

void PacketHandler(u_char* args, const pcap_pkthdr* header, const u_char* packet) {
    /* Layer Filter Array */
    std::vector<FilterInterface*> filters = CreateLayerFilterArray();

    // Extract the packet arguments
    PacketArgs* packet_args_ptr = (PacketArgs*)(args);

    packet_args_ptr->packet_count_++;
    std::cout << "Packet number " << packet_args_ptr->packet_count_ << "\n\n";

    /* To store the starting point of the new layer header */
    uint start = 0;

    /* Iterate and parse through all Layer Header filters */
    for (int i = 0; i < filters.size(); i++) {
        /* Parse the packet from the given starting point and print */
        filters[i]->Parse(packet, start);
        filters[i]->Print();
        start = start + filters[i]->GetHeaderSize();
    }

    /* Free the allocated layer filter pointers */
    FreeLayerFilterArray(filters);

    PrintSeperator('-', GetTerminalWidth());
}

uint CheckFilePath(std::string file_path) {
    size_t index = file_path.find_last_of('/');
    // Extract the directory path and file name
    std::string directory_path = file_path.substr(0, index);
    std::string file_name = file_path.substr(index + 1, file_path.size() - index);

    // Check whether directory exists or not
    struct stat buffer;
    if (stat(directory_path.c_str(), &buffer) != 0) {
        std::cout << "Directory does not exist, creating directory " << directory_path << "\n\n";

        if (mkdir(directory_path.c_str(), 0777) == -1) {
            std::cerr << "Could not create directory.\n\n";
            return -1;
        } else {
            std::cout << "Created directory " << directory_path << "\n\n";
        }
    }

    return 0;
}