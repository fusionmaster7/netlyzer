/* Header declaration for the sniffer class */
#ifndef SNIFFER_H
#define SNIFFER_H

#include "network_filters.h"
#include "utils.h"

/* Number of packets to be read */
const int PACKET_COUNT = 1;

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
    /* Class constructor */
    Sniffer();

    /* Gets the device name */
    std::string GetDeviceName();
    /* Gets the protocol name */
    std::string GetProtocolName();
    /* Gets the port number */
    std::string GetPortNumber();

    /* Sets the device name */
    void SetDeviceName(std::string device_name);
    /* Sets the protocol name */
    void SetProtocolName(std::string protocol);
    /* Sets the port number */
    void SetPortNumber(std::string port);

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
