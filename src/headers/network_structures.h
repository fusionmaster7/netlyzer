#ifndef ETHERNET_H
#define ETHERNET_H

#include "includes.h"

/* ------ Ethernet Frames Parsing Structure ----- */

/* Ethernet frames are always 14 bytes */
const int ETHERNET_HEADER_SIZE = 14;
const int ETHERNET_ADDRESS_SIZE = 6;
const int ETHERNET_TYPE_SIZE = 2;

struct Ethernet {
    /* Destination Mac Address */
    u_char d_mac_[ETHERNET_ADDRESS_SIZE];
    /* Source Mac Address */
    u_char s_mac_[ETHERNET_ADDRESS_SIZE];
    /* Eth Type */
    u_char eth_type_[ETHERNET_TYPE_SIZE];
};

/* ----- Internet Layer Parsing Structure */

#endif