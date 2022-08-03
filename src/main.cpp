#include "./headers/includes.h"
#include "./headers/sniffer.h"
#include "./headers/utils.h"

/**
 * TODO: Add a file check middleware which verifies that the file path directory exists or not and if not create it.
 * TODO: Add filter flag.
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

/* Function to parse command line options and set them into the config number */
void ParseCommand(int argc, char* argv[], uint& config, ConfigValues& config_values) {
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
                CopyArg(config_values.device_name_, argv[i]);
            } else if (ch == 'f') {
                SetOption(config, FILTER_OPTION_MASK);
                i++;

                /* Copy value of arg in filter expression string */
                CopyArg(config_values.filter_exp_, argv[i]);
            } else if (ch == 'm') {
                SetOption(config, OFFLINE_MODE_MASK);
                i++;

                /* Copy value in capture file import string */
                CopyArg(config_values.capture_file_path_, argv[i]);
            } else if (ch == 'e') {
                SetOption(config, DUMP_FILE_MASK);
                i++;

                /* Copy value in dump file path string */
                CopyArg(config_values.dump_file_path_, argv[i]);
            } else if (ch == 'c') {
                SetOption(config, PACKET_COUNT_MASK);
                i++;
                config_values.packets_to_read_ = atoi(argv[i]);
            }
        }

        i++;
    }
}

/* Build the sniffer object based on Args passed */
Sniffer BuildSniffer(uint& config, ConfigValues& config_values) {
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
            std::cin >> config_values.device_name_;
        } else {
            SetOption(config, OFFLINE_MODE_MASK);
            std::cout << "Enter the capture file path: ";
            std::cin >> config_values.capture_file_path_;
        }
    }

    /* Check for conflicts */
    if (CheckOption(config, DEVICE_OPTION_MASK) && CheckOption(config, OFFLINE_MODE_MASK)) {
        std::cerr << "Please enter only one option: -d for Online Mode, -m for Offline Mode\n";
        exit(1);
    }

    /* If in online mode, create the device sniffer */
    if (CheckOption(config, DEVICE_OPTION_MASK)) {
        sniffer.SetDeviceName(config_values.device_name_);
        sniffer.CreateSniffer();
    }

    /* If in online mode, set sniffer from file */
    if (CheckOption(config, OFFLINE_MODE_MASK)) {
        sniffer.CreateSnifferFromFile(config_values.capture_file_path_);
    }

    return sniffer;
}

// Set arguments to be passed in the callback function for reading packets
void SetCallbackArgs(uint& config, ConfigValues& config_values, PacketArgs& args) {
    args.packet_count_ = 0;
    args.dump_file_path_ = "";

    // If dump file flag has been set, set the path in config args
    if (CheckOption(config, DUMP_FILE_MASK)) {
        args.dump_file_path_ = config_values.dump_file_path_;
    }

    // If packet count has not been specified, set the default packet count
    if (!CheckOption(config, PACKET_COUNT_MASK)) {
        config_values.packets_to_read_ = 1;
    }
}

int main(int argc, char* argv[]) {
    /* Configuration Number. We can find out whether certain params have been set using their masks. */
    uint config = (0 << CONFIG_BIT_SIZE);

    /* Config Values Struct */
    ConfigValues config_values;

    /* Parse the args, set flags and store arg values */
    ParseCommand(argc, argv, config, config_values);

    Sniffer sniffer = BuildSniffer(config, config_values);

    PacketArgs args;

    SetCallbackArgs(config, config_values, args);

    // Check if data needs to be exported to a file or displayed on the console.
    if (CheckOption(config, DUMP_FILE_MASK)) {
        // Check if file path exists or not, if not then create it.
        // -1 means the file path could not be created.
        if (CheckFilePath(args.dump_file_path_) == -1) {
            return -1;
        }
        sniffer.WriteToFile(args);
    } else {
        sniffer.Read(PacketHandler, args, config_values.packets_to_read_);
    }

    /* Close the device sniffer if running in online mode */
    if (CheckOption(config, DEVICE_OPTION_MASK)) {
        sniffer.Close();
    }

    return 0;
}
