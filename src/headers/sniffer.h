/* Header declaration for the sniffer class */
#ifndef SNIFFER_H
#define SNIFFER_H

#include "network_filters.h"
#include "utils.h"

/* Number of packets to be read */
const int PACKET_COUNT = 1;

/* ----- Parameter Masks (Each bit denotes a different option) ----- */

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
    /* Name of the protocol to sniff */
    std::string protocol_;
    /* Port on which we have to listen */
    std::string port_;

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

    /* Sets the device name */
    void SetDeviceName(std::string device_name);

    /* Creates the sniffer device object */
    void Open();
    /* Close the sniffer device object */
    void Close();
    /* Method to start reading the packets */
    void Read();

    /* Assign custom sniffer struct */
    void SetSniffer(pcap_t* sniffer);
};

/* Test function to list all devices */
void ListDevices();

/* Callback function to handle packets */
void PacketHandler(u_char* args, const pcap_pkthdr* header, const u_char* packet);

#endif
