#include "./headers/network_filters.h"

/* ----- Ethernet Layer Definition ----- */

EthernetLayerFilter::EthernetLayerFilter() {
    this->eth_struct_ = nullptr;
}

void EthernetLayerFilter::Parse(const u_char* packet, uint start) {
    this->eth_struct_ = (ether_header*)(packet + start);
}

void EthernetLayerFilter::Print() {
    std::cout << "Source MAC address is " << ConvertToHexadecimal(this->eth_struct_->ether_shost, ETH_ALEN) << "\n";
    std::cout << "Destination MAC address is " << ConvertToHexadecimal(this->eth_struct_->ether_dhost, ETH_ALEN) << "\n";

    if (BtoHex2(this->eth_struct_->ether_type) == ETHERTYPE_IP) {
        std::cout << "Ethertype is IPv4"
                  << "\n\n";
    }
}

/* ----- Network Layer Definition ----- */

NetworkLayerFilter::NetworkLayerFilter() {
    this->ip_struct_ = nullptr;
}

void NetworkLayerFilter::Parse(const u_char* packet, uint start) {
    this->ip_struct_ = (ip*)(packet + start);
}

void NetworkLayerFilter::Print() {
    std::string src_ip(inet_ntoa(ip_struct_->ip_src));
    std::string dest_ip(inet_ntoa(ip_struct_->ip_dst));

    std::cout << "Source IP Address is " << src_ip << "\n";
    std::cout << "Destination IP Address is " << dest_ip << "\n\n";
}