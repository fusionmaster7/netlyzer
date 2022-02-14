#include "./headers/sniffer.h"

Sniffer::Sniffer() {
    this->device_sniffer_ = nullptr;
}

std::string Sniffer::GetDeviceName() {
    return this->device_name_;
}

std::string Sniffer::GetProtocolName() {
    return this->protocol_;
}

std::string Sniffer::GetPortNumber() {
    return this->port_;
}

void Sniffer::SetDeviceName(std::string device_name) {
    this->device_name_ = device_name;
}

void Sniffer::SetProtocolName(std::string protocol) {
    this->protocol_ = protocol;
}

void Sniffer::SetPortNumber(std::string port) {
    this->port_ = port;
}

void Sniffer::Open() {
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

void Sniffer::Close() {
    pcap_close(this->device_sniffer_);
    std::cout << "Closed sniffer for device " << this->device_name_ << "\n";
}

void PacketHandler(u_char* args, const pcap_pkthdr* header, const u_char* packet) {
    /* Typecast the value of args from u_char to u_int */
    uint* packet_count = reinterpret_cast<uint*>(args);
    (*packet_count)++;
    std::cout << "Packet number " << *(packet_count) << ":\n\n";

    /* Parse Ethernet header */
    EthernetLayerFilter eth;
    eth.Parse(packet, 0);

    /* Print Ethernet Header */
    eth.Print();

    /* Parse IP Layer header */
    NetworkLayerFilter ip;
    ip.Parse(packet, sizeof(ether_header));

    /* Print Network Header */
    ip.Print();

    if (*packet_count < PACKET_COUNT) {
        PrintSeperator('-', GetTerminalWidth());
    }
}

void Sniffer::Read() {
    /* Pointer to the packet count variable */
    uint packet_count = 0;
    uint* packet_count_ptr = &packet_count;

    /* Typecast to pass as args in the callback function */
    u_char* args = reinterpret_cast<u_char*>(packet_count_ptr);

    /* Read the specified packets on the opened device and call the handler on each of them */
    pcap_loop(this->device_sniffer_, PACKET_COUNT, PacketHandler, args);

    PrintSeperator('-', GetTerminalWidth());
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