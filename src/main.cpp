#include "./headers/includes.h"
#include "./headers/sniffer.h"

/*TODO:
    1. Parse Packet headers
    2. Parse Packet payload
*/

/* Dumped file path for testing */
std::string FILE_PATH = "/home/hardik/wireshark_captures/general_capture.pcapng";

/* Function to copy char pointer into the passed string */
void CopyArg(std::string& param, char* arg) {
    char* ch = arg;
    while (*ch != '\0') {
        param.push_back(*ch);
        ch++;
    }
}

/* Check if application is in testing(offline) mode */
bool IsTesting(int argc, char* argv[]) {
    /* Extract last arg passed */
    std::string last_param(argv[argc - 1]);

    /* Check if the last arg is test or not */
    return (last_param.compare("test") == 0);
}

/* Function to parse command line options and return an object of Sniffer class */
Sniffer ParseCommand(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Please enter options and try again.\n";
        exit(1);
    }

    /* Device string */
    std::string device;

    /* Filter string */
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

    /* Open application in testing mode */
    if (IsTesting(argc, argv)) {
        /* Buffer to store errors */
        char* errbuf;
        pcap_t* offline_sniffer = pcap_open_offline(FILE_PATH.c_str(), errbuf);

        /* Check for errors in opening dump file */
        if (!offline_sniffer) {
            std::cout << "Error in opening dump file.\n";
            puts(errbuf);
        } else {
            /* Set sniffer object and read from file */
            sniffer.SetSniffer(offline_sniffer);
            sniffer.Read();
        }
    } else {
        /* Open the device sniffer */
        sniffer.Open();

        /* Read the packets from device */
        sniffer.Read();

        /* Close the sniffer */
        sniffer.Close();
    }

    return 0;
}
