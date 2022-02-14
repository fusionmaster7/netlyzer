/* Network Filters Declaration File */

#ifndef NETWORK_FILTERS_H
#define NETWORK_FITLERS_H

#include "includes.h"
#include "utils.h"

/* ----- Layer Header Parsing Interface ----- */
class LayerFilterInterface {
   public:
    /* Abstract Method to filter packet and parse corresponding layer header */
    virtual void Parse(const u_char* packet, uint start) = 0;

    /* Abstract Method to print header details */
    virtual void Print() = 0;
};

/* ----- Ethernet Layer Header Parsing Class ----- */
class EthernetLayerFilter : public LayerFilterInterface {
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
};

/* ----- Network Layer Header Parsing Class ----- */
class NetworkLayerFilter : public LayerFilterInterface {
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
};

#endif