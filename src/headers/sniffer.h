/* Header declaration for the sniffer class */
#ifndef SNIFFER_H
#define SNIFFER_H

#include "network_filters.h"
#include "utils.h"

// Number of bits required to denote the configuration bitset */
const uint CONFIG_BIT_SIZE = 10;

/* ----- Parameter Masks (Each bit denotes a different option) ----- */

/* Mask to check whether packet count has been specified or not */
const uint PACKET_COUNT_MASK = 7;

/* Mask to check whether to export file or not */
const uint DUMP_FILE_MASK = 6;

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

    // Method to start reading the packets
    // target_packets is the number of packets to read
    void Read(pcap_handler packet_handler, PacketArgs packet_args, int target_packets);

    /* Close the sniffer device object */
    void Close();
};

/* Test function to list all devices */
void ListDevices();

#endif
