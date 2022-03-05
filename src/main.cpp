#include "./headers/includes.h"
#include "./headers/sniffer.h"

/*TODO:
    1. Add flags for the following:
        a. Interactive mode (-i)
        b. Online or Offline mode (-o or -d)
        c. Filter expressions (-f)
    2. Add options to dump capture file
*/

/* Function to copy char pointer into the passed string */
void CopyArg(std::string& param, char* arg) {
    char* ch = arg;
    while (*ch != '\0') {
        param.push_back(*ch);
        ch++;
    }
}

/* Checks whether a certain param has been set in the config or not */
bool CheckOption(uint& config, const uint param_mask) {
    return (config & (1 << param_mask));
}

void SetOption(uint& config, const uint param_mask) {
    /* Set the corresponding bit in the config number using param mask */
    config = (config | (1 << param_mask));
}

/* Function to parse command line options, set them into the config number and and return an object of Sniffer class */
Sniffer ParseCommand(int argc, char* argv[], uint& config, std::string& device_name, std::string filter_exp) {
    if (argc < 2) {
        std::cerr << "Please enter options and try again.\n";
        exit(1);
    }

    /* Iterate through all params passed and check for flags */
    int i = 1;
    while (i < argc) {
        /* Store the param in String class object */
        std::string option(argv[i]);

        /* Check whether option flag or not */
        if (option[0] == '-') {
            char ch = option[1];

            /* Interactive mode */
            if (ch == 'i') {
                SetOption(config, INTERACTIVE_OPTION_MASK);

                /* There should not be any other options after interactive mode flag */
                if (argc > 2) {
                    std::cerr << "Too many flags for interactive mode. Please check and try again.\n";
                    exit(1);
                }

            } else if (ch == 'd') {
                SetOption(config, DEVICE_OPTION_MASK);
                i++;

                /* Copy value of arg in device string */
                CopyArg(device_name, argv[i]);
            } else if (ch == 'f') {
                SetOption(config, FILTER_OPTION_MASK);
                i++;

                /* Copy value of arg in filter expression string */
                CopyArg(filter_exp, argv[i]);
            }
        }

        i++;
    }

    /* Create an object of the sniffer class */
    Sniffer sniffer;

    return sniffer;
}

int main(int argc, char* argv[]) {
    /* Configuration Number. We can find out whether certain params have been set using their masks. */
    uint config = (0 << 4);

    /* String to store device name */
    std::string device_name;

    /* String to store filter expression */
    std::string filter_exp;

    Sniffer sniffer = ParseCommand(argc, argv, config, device_name, filter_exp);

    /* Buffer to store error */
    char err_buf[BUFSIZ];

    /* Check if the application is running in interactive mode */
    if (CheckOption(config, INTERACTIVE_OPTION_MASK)) {
        std::cout << "Do you want to start the application in Live(online) Mode? (y/n) ";
        char resp;

        /* Take user response and convert to lowercase */
        std::cin >> resp;
        resp = tolower(resp);

        if (resp == 'y') {
            /* Start the tool in online mode */
            std::cout << "Enter device name: ";
            std::cin >> device_name;

            sniffer.SetDeviceName(device_name);

            sniffer.Open();
            sniffer.Read();
            sniffer.Close();

        } else {
            /* Start the tool in offline mode */
            std::string file_name;
            std::cout << "Enter name of dump file: ";
            std::cin >> file_name;

            pcap_t* offline_sniffer = pcap_open_offline(file_name.c_str(), err_buf);

            /* Check if file opened successfully */
            if (!offline_sniffer) {
                std::cerr << "Error opening dump file. Following error encountered:\n";
                puts(err_buf);
                exit(1);
            }

            /* Set offline sniffer */
            sniffer.SetSniffer(offline_sniffer);
            sniffer.Read();
        }
    } else {
        /* Check whether device flag has been set or not */
        if (CheckOption(config, DEVICE_OPTION_MASK)) {
            /* Open device and start reading */
            sniffer.SetDeviceName(device_name);
            sniffer.Open();
            sniffer.Read();

            sniffer.Close();
        } else {
            std::cerr << "Please select a device an0d try again.\n";
            exit(1);
        }
    }

    return 0;
}
