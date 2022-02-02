#include <pcap/pcap.h>

#include <iostream>

int main(int argc, char* argv[]) {
    pcap_if_t* head;
    char errbuf[PCAP_ERRBUF_SIZE];

    int status = pcap_findalldevs(&head, errbuf);
    if (status != 0) {
        std::cerr << "Some error occured while finding the devices.\n";
        exit(1);
    }

    pcap_if_t* ptr = head;
    while (ptr) {
        std::cout << "Name of device is ";
        puts(ptr->name);

        if (ptr->description) {
            puts(ptr->description);
        } else {
            std::cout << "Device description not available.\n";
        }
        ptr = ptr->next;
    }

    return 0;
}