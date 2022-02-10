#include "./headers/includes.h"
#include "./headers/sniffer.h"

/*TODO:
    1. Create a sniffer class
    2. Start sniffing an arbitrary packet
    3. Parse Packet data
    4. Add option in Sniffer class structure for number of packets to be parsed
    4. Add options for flags
*/

/* Function to copy char pointer into the passed string */
void CopyArg(std::string& param, char* arg) {
    char* ch = arg;
    while (*ch != '\0') {
        param.push_back(*ch);
        ch++;
    }
}

/* Function to parse command line options and return an object of Sniffer class */
Sniffer ParseCommand(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Please enter options and try again.\n";
        exit(1);
    }

    std::string device;
    std::string filter;

    for (int i = 1; i < argc; i++) {
        /* Check for arguments */
        char* ch = argv[i];
        if (*ch == '-') {
            /* Check whether device argument or filter argument */
            char arg = *(ch + 1);
            if (arg == DEVICE_ARG) {
                CopyArg(device, argv[i + 1]);
                i++;
            }
        }
    }

    /* Create an object of the sniffer class */
    Sniffer sniffer;
    sniffer.SetDeviceName(device);

    return sniffer;
}

int main(int argc, char* argv[]) {
    Sniffer sniffer = ParseCommand(argc, argv);
    sniffer.Open();

    sniffer.Read();

    sniffer.Close();

    return 0;
}
