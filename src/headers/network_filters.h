/* Network Filters Declaration File */

#ifndef NETWORK_FILTERS_H
#define NETWORK_FILTERS_H

#include "includes.h"
#include "utils.h"

/* ----- Layer Header Parsing Interface ----- */
class FilterInterface {
   public:
    /* Abstract Method to filter packet and parse corresponding layer header */
    virtual void Parse(const u_char* packet, uint start) = 0;

    /* Abstract Method to print header details */
    virtual void Print() = 0;

    /* Return the size of that corresponding layer header */
    virtual uint GetHeaderSize() = 0;
};

/* ----- Ethernet Layer Header Parsing Class ----- */
class EthernetLayerFilter : public FilterInterface {
   private:
    /* Structure to store the header */
    ether_header* eth_struct_;

   public:
    /* Default Class Constructor */
    EthernetLayerFilter();

    /* Overriden method to parse ethernet layer header */
    void Parse(const u_char* packet, uint start) override;

    /* Print ethernet header details */
    void Print() override;

    /* Return ethernet header size */
    uint GetHeaderSize();
};

/* ----- Network Layer Header Parsing Class ----- */
class NetworkLayerFilter : public FilterInterface {
   private:
    /* Structure to store the header */
    ip* ip_struct_;

   public:
    /* Default Class Constructor */
    NetworkLayerFilter();

    /* Overriden method to parse network layer header */
    void Parse(const u_char* packet, uint start) override;

    /* Print network layer header details */
    void Print() override;

    /* Return Network Layer header size */
    uint GetHeaderSize();

    std::string SetUpperLayerProtocol(uint8_t proto);
};

/* ----- Transport Layer Header Parsing Classes ----- */
/* ----- Abstract Class for Transport Layer Protocol ----- */

/* ----- TCP Protocol Header Class ----- */
class TCPFilter : public FilterInterface {
   private:
    /* ----- TCP header struct ----- */
    tcphdr* tcp_struct_;

   public:
    /* TCP Filter Constructor */
    TCPFilter();

    /* To Parse TCP protcol header */
    void Parse(const u_char* packet, uint start) override;

    /* To Print TCP protocol header */
    void Print() override;

    /* To get TCP Header size */
    uint GetHeaderSize() override;
};

/* ----- UDP Protocol Header Class ----- */
class UDPFilter : public FilterInterface {
   private:
    /* ----- UDP header struct ----- */
    udphdr* udp_struct_;

   public:
    /* UDP Filter Constructor */
    UDPFilter();

    /* To Parse UDP protcol header */
    void Parse(const u_char* packet, uint start) override;

    /* To Print UDP protocol header */
    void Print() override;

    /* To get UDP Header size */
    uint GetHeaderSize() override;
};

/* ----- Transport Layer Filter Class ----- */
class TransportLayerFilter : public FilterInterface {
   private:
    /* To store transport layer protocol header */
    FilterInterface* protocol_header_;

   public:
    /* Default Class Constructor */
    TransportLayerFilter();

    /* Parameterised Class Constructor */
    TransportLayerFilter(FilterInterface* protocol_header);

    /* To set protocol type header accordingly */
    void SetProtocol(FilterInterface* protocol_header);

    /* Overriden method to parse transport layer header */
    void Parse(const u_char* packet, uint start) override;

    /* Overriden method to print transport layer header */
    void Print() override;

    /* Overriden method to return header size */
    uint GetHeaderSize() override;

    /* Class Destructor */
    ~TransportLayerFilter();
};

/* Returns an array with all the layer filters pointers as its members */
std::vector<FilterInterface*>
CreateLayerFilterArray();

/* Free the allocated memory pointers */
void FreeLayerFilterArray(std::vector<FilterInterface*>& filters);

#endif