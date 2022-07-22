/* Header declaration for the sniffer class */
#ifndef SNIFFER_H
#define SNIFFER_H

#include "network_filters.h"
#include "utils.h"

/* Number of packets to be read */
const int PACKET_COUNT = 1;

/* ----- Parameter Masks (Each bit denotes a different option) ----- */

/* Mask to check whether offline mode or not */
const uint OFFLINE_MODE_MASK = 5;

/* Mask to check whether interactive mode or not */
const uint INTERACTIVE_OPTION_MASK = 4;

/* Mask to check whether device has been set or not */
const uint DEVICE_OPTION_MASK = 3;

/* Mask to check whether filter has been set or not */
const uint FILTER_OPTION_MASK = 2;

class Sniffer {
   private:
    /* Name of the device to listen to */
    std::string device_name_;

    /* Traffic Filter Expression Structure */
    bpf_program filter_;

    /* Pair to hold network address and mask of device */
    std::pair<bpf_u_int32, bpf_u_int32> device_network_;

    /* Actual sniffer structure */
    pcap_t* device_sniffer_;

    /* Error buffer */
    char errbuf_[PCAP_ERRBUF_SIZE];

   public:
    /* Default Class constructor */
    Sniffer();

    /* Parameterised Class constructor */
    Sniffer(pcap_t* sniffer);

    /* Gets the device name */
    std::string GetDeviceName();

    /* To find network address and mask of device */
    void GetNetMask();

    /* Assign custom sniffer struct */
    void SetSniffer(pcap_t* sniffer);

    /* To compile and set device filter */
    void SetFilter(std::string filter_exp);

    /* Sets the device name */
    void SetDeviceName(std::string device_name);

    /* Creates the sniffer device object */
    void CreateSniffer();

    /* Creates and stores sniffer from custom capture file */
    void CreateSnifferFromFile(std::string file_path);

    /* Method to start reading the packets */
    void Read();

    /* Close the sniffer device object */
    void Close();
};

/* Test function to list all devices */
void ListDevices();

/* Callback function to handle packets */
void PacketHandler(u_char* args, const pcap_pkthdr* header, const u_char* packet);

#endif
