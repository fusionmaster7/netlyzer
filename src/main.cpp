#include "./headers/includes.h"
#include "./headers/sniffer.h"

/*TODO:
    1. Add flags for the following:
        a. Interactive mode (-i)
        b. Online or Offline mode (-o or -d)
        c. Filter expressions (-f)
    2. Rewrite Sniffer object building code
    2. Add options to dump capture file
*/

/* Struct to hold Arg values */
struct ConfigValues {
    /* Device Name */
    std::string device_name_;
    /* Filter Expression */
    std::string filter_exp_;
    /* Path to read packets from in offline mode */
    std::string capture_file_path_;
    /* Path to export capture */
    std::string dump_file_path_;
};

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

/* Function to parse command line options and set them into the config number */
void ParseCommand(int argc, char* argv[], uint& config, ConfigValues& configValues) {
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
                /* Reset all other flags */
                config = (0 << 7);
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
                CopyArg(configValues.device_name_, argv[i]);
            } else if (ch == 'f') {
                SetOption(config, FILTER_OPTION_MASK);
                i++;

                /* Copy value of arg in filter expression string */
                CopyArg(configValues.filter_exp_, argv[i]);
            } else if (ch == 'm') {
                SetOption(config, OFFLINE_MODE_MASK);
                i++;

                /* Copy value in capture file import string */
                CopyArg(configValues.capture_file_path_, argv[i]);
            }
        }

        i++;
    }
}

/* Build the sniffer object based on Args passed */
Sniffer BuildSniffer(uint& config, ConfigValues& configValues) {
    /* Sniffer Object. We'll build the object progressively according to options set */
    Sniffer sniffer;

    /* Check if Interactive Mode has been set or not */
    if (CheckOption(config, INTERACTIVE_OPTION_MASK)) {
        char ch;

        std::cout << "Do you want to start the application in online mode? (y/n) ";
        std::cin >> ch;

        if (tolower(ch) == 'y') {
            SetOption(config, DEVICE_OPTION_MASK);
            std::cout << "Enter the device(interface) name: ";
            std::cin >> configValues.device_name_;
        } else {
            SetOption(config, OFFLINE_MODE_MASK);
            std::cout << "Enter the capture file path: ";
            std::cin >> configValues.capture_file_path_;
        }
    }

    /* Check for conflicts */
    if (CheckOption(config, DEVICE_OPTION_MASK) && CheckOption(config, OFFLINE_MODE_MASK)) {
        std::cerr << "Please enter only one option: -d for Online Mode, -m for Offline Mode\n";
        exit(1);
    }

    /* If in online mode, create the device sniffer */
    if (CheckOption(config, DEVICE_OPTION_MASK)) {
        sniffer.SetDeviceName(configValues.device_name_);
        sniffer.CreateSniffer();
    }

    /* If in online mode, set sniffer from file */
    if (CheckOption(config, OFFLINE_MODE_MASK)) {
        sniffer.CreateSnifferFromFile(configValues.capture_file_path_);
    }

    return sniffer;
}

int main(int argc, char* argv[]) {
    /* Configuration Number. We can find out whether certain params have been set using their masks. */
    uint config = (0 << 7);

    /* Config Values Struct */
    ConfigValues configValues;

    /* Parse the args, set flags and store arg values */
    ParseCommand(argc, argv, config, configValues);

    Sniffer sniffer = BuildSniffer(config, configValues);

    sniffer.Read();

    /* Close the device sniffer if running in online mode */
    if (CheckOption(config, DEVICE_OPTION_MASK)) {
        sniffer.Close();
    }

    return 0;
}
