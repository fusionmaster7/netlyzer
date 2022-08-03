#include "./headers/sniffer.h"

Sniffer::Sniffer() {
    this->device_sniffer_ = nullptr;
}

Sniffer::Sniffer(pcap_t* sniffer) {
    this->device_sniffer_ = sniffer;
}

std::string Sniffer::GetDeviceName() {
    return this->device_name_;
}

void Sniffer::SetDeviceName(std::string device_name) {
    this->device_name_ = device_name;
}

void Sniffer::CreateSniffer() {
    /* Open the device and assign the value to sniffer struct */
    this->device_sniffer_ = pcap_open_live(this->device_name_.c_str(), BUFSIZ, 1, 1000, this->errbuf_);

    /* Check for errors */
    if (this->device_sniffer_ == nullptr) {
        std::cerr << "Error opening device. Following error encountered: \n";
        puts(this->errbuf_);
        exit(1);
    }

    /* Check if link layer headers are supported or not */
    if (pcap_datalink(this->device_sniffer_) != DLT_EN10MB) {
        std::cerr << "Device does not support ethernet frame headers.\n";
        exit(1);
    }

    std::cout << "Opened device " << this->device_name_ << "\n";
    PrintSeperator('-', GetTerminalWidth());
}

void Sniffer::CreateSnifferFromFile(std::string file_path) {
    this->device_sniffer_ = pcap_open_offline(file_path.c_str(), this->errbuf_);
}

void Sniffer::Close() {
    pcap_close(this->device_sniffer_);
    std::cout << "Closed sniffer for device " << this->device_name_ << "\n";
}

void Sniffer::Read(pcap_handler packet_handler, PacketArgs packet_args, int target_packets) {
    /* Pointer to the packet count variable */
    uint packet_count = 0;

    // packet_args are the additional arguments that need to be passed to the function.
    // We need to cast it to the appropriate type to pass to the callback
    u_char* args = reinterpret_cast<u_char*>(&packet_args);

    /* Read the specified packets on the opened device and call the handler on each of them */
    pcap_loop(this->device_sniffer_, target_packets, packet_handler, args);
}

void Sniffer::WriteToFile(PacketArgs packet_args) {
    if (packet_args.dump_file_path_.compare("") == 0) {
        std::cerr << "Please enter the file path.\n\n";
        return;
    }

    pcap_dumper_t* pd = pcap_dump_open(this->device_sniffer_, packet_args.dump_file_path_.c_str());

    if (pd == NULL) {
        std::cerr << "Could not open dump file. Please check path and try again.\n\n";
        return;
    }

    int captured_packet_count = pcap_dispatch(this->device_sniffer_, packet_args.packet_count_, &pcap_dump, (u_char*)pd);

    if (captured_packet_count < 0) {
        std::cerr << "Error reading packets from interface.\n\n";
    }

    pcap_dump_close(pd);
}

void Sniffer::SetSniffer(pcap_t* sniffer) {
    this->device_sniffer_ = sniffer;
}

void Sniffer::GetNetMask() {
    /* Create network and mask variables */
    bpf_u_int32 net;
    bpf_u_int32 mask;

    if (pcap_lookupnet(this->device_name_.c_str(), &net, &mask, this->errbuf_) == -1) {
        std::cerr << "Error in obtaining network address for device. Following error encountered:\n";
        puts(this->errbuf_);
        exit(1);
    }

    /* Set the network and mask values */
    this->device_network_.first = net;
    this->device_network_.second = mask;
}

void Sniffer::SetFilter(std::string filter_exp) {
    /* Compile the filter and then store the filter expression in the assigned structure */
    if (pcap_compile(this->device_sniffer_, &this->filter_, filter_exp.c_str(), 0, this->device_network_.first) == -1) {
        std::cerr << "Could not compile filter " << filter_exp << "  for device " << this->device_name_ << "\n";
        exit(1);
    }

    /* Set the compiled filter expression */
    if (pcap_setfilter(this->device_sniffer_, &this->filter_) == -1) {
        std::cerr << "Could not set filter " << filter_exp << " for device " << this->device_name_ << "\n";
        exit(1);
    }
}

void ListDevices() {
    /* Head of linked list of device structs */
    pcap_if_t* head;
    char errbuf[PCAP_ERRBUF_SIZE];

    int status = pcap_findalldevs(&head, errbuf);
    if (status != 0) {
        std::cerr << "Could not find devices.\n";
        exit(1);
    }

    pcap_if_t* ptr = head;
    while (ptr) {
        puts(ptr->name);
        ptr = ptr->next;
    }

    pcap_freealldevs(head);
}