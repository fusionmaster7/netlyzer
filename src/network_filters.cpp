#include "./headers/network_filters.h"

/* ----- GLOBAL PROTOCOL FLAGS ----- */
uint TRANSPORT_LAYER_PROTOCOL = -1;

/* ----- Ethernet Layer Filter Definition ----- */
EthernetLayerFilter::EthernetLayerFilter() {
    this->eth_struct_ = nullptr;
}

void EthernetLayerFilter::Parse(const u_char* packet, uint start) {
    this->eth_struct_ = (ether_header*)(packet + start);
}

void EthernetLayerFilter::Print() {
    std::cout << "Ethernet Layer Header:\n";
    std::cout << "Source MAC address is " << ConvertToHexadecimal(this->eth_struct_->ether_shost, ETH_ALEN) << "\n";
    std::cout << "Destination MAC address is " << ConvertToHexadecimal(this->eth_struct_->ether_dhost, ETH_ALEN) << "\n";

    std::string ether_type;

    uint16_t ether_type_value = ntohs(this->eth_struct_->ether_type);

    if (ether_type_value == ETHERTYPE_ARP) {
        ether_type = "ARP";
    } else if (ether_type_value == ETHERTYPE_IP) {
        ether_type = "IPv4";
    }

    std::cout << "Ethertype is " << ether_type << "\n";

    std::cout << "\n";
}

uint EthernetLayerFilter::GetHeaderSize() {
    return sizeof(ether_header);
}

/* ----- Network Layer Filter Definition ----- */

NetworkLayerFilter::NetworkLayerFilter() {
    this->ip_struct_ = nullptr;
}

void NetworkLayerFilter::Parse(const u_char* packet, uint start) {
    this->ip_struct_ = (ip*)(packet + start);
    TRANSPORT_LAYER_PROTOCOL = this->ip_struct_->ip_p;
}

void NetworkLayerFilter::Print() {
    std::cout << "Network Layer Header:\n";

    std::string ip_ver;
    if (this->ip_struct_->ip_v == IPVERSION) {
        ip_ver = "IPv4";
    }

    std::cout << "Unique identifier is " << ntohs(this->ip_struct_->ip_id) << "\n";
    std::cout << "IP Version is " << ip_ver << "\n";

    /* We mulitply by 4 because ip_hl gives length in terms of 32 bits (4 byte) words. Valid for only IPv4 */
    std::cout << "Length of Network Layer Header is " << (this->ip_struct_->ip_hl * 4) << " bytes\n";

    std::cout << "Upper layer protocol is " << this->SetUpperLayerProtocol(this->ip_struct_->ip_p) << "\n";

    std::cout << "Time to live for packet is " << (uint)this->ip_struct_->ip_ttl << " hops\n";

    std::string src_ip(inet_ntoa(ip_struct_->ip_src));
    std::string dest_ip(inet_ntoa(ip_struct_->ip_dst));

    std::cout << "Source IP Address is " << src_ip << "\n";
    std::cout << "Destination IP Address is " << dest_ip << "\n";

    std::cout << "\n";
}

uint NetworkLayerFilter::GetHeaderSize() {
    return (this->ip_struct_->ip_hl) * 4;
}

std::string NetworkLayerFilter::SetUpperLayerProtocol(uint8_t proto) {
    std::string protocol;

    if (proto == IPPROTO_TCP) {
        protocol = "TCP";
    } else if (proto == IPPROTO_UDP) {
        protocol = "UDP";
    }

    return protocol;
}

/* ----- Transport Layer Filter Definition ----- */
/* ----- TCP Protocol Filter Definition ----- */

TCPFilter::TCPFilter() {
    this->tcp_struct_ = nullptr;
}

void TCPFilter::Parse(const u_char* packet, uint start) {
    this->tcp_struct_ = (tcphdr*)(packet + start);
}

void TCPFilter::Print() {
    std::cout << "Transport Protocol is TCP\n";
    std::cout << "Source port is " << ntohs(this->tcp_struct_->th_sport) << "\n";
    std::cout << "Destination port is " << ntohs(this->tcp_struct_->th_dport) << "\n";
    /* Same reason as for network layer, the unit is 4 byte words */
    std::cout << "The length of TCP header is " << this->GetHeaderSize() << " bytes\n";
}

uint TCPFilter::GetHeaderSize() {
    return this->tcp_struct_->doff * 4;
}

/* ----- UDP Protocol Filter Definition ----- */
UDPFilter::UDPFilter() {
    this->udp_struct_ = nullptr;
}

void UDPFilter::Parse(const u_char* packet, uint start) {
    this->udp_struct_ = (udphdr*)(packet + start);
}

void UDPFilter::Print() {
    std::cout << "Transport Protocol is UDP\n";
    std::cout << "Source port is " << ntohs(this->udp_struct_->uh_sport) << "\n";
    std::cout << "Destination port is " << ntohs(this->udp_struct_->uh_dport) << "\n";
    std::cout << "The length of UDP header is " << this->GetHeaderSize() << " bytes\n";
}

uint UDPFilter::GetHeaderSize() {
    return sizeof(udphdr);
}

/* ----- Transport Layer Filter Definition ----- */
TransportLayerFilter::TransportLayerFilter() {
    this->protocol_header_ = nullptr;
}

TransportLayerFilter::TransportLayerFilter(FilterInterface* protocol_header) {
    this->protocol_header_ = protocol_header;
}

void TransportLayerFilter::SetProtocol(FilterInterface* protocol_header) {
    this->protocol_header_ = protocol_header;
}

void TransportLayerFilter::Parse(const u_char* packet, uint start) {
    FilterInterface* protocol_filter = nullptr;

    /* Create protocol header accordingly */
    if (TRANSPORT_LAYER_PROTOCOL == IPPROTO_TCP) {
        protocol_filter = new TCPFilter();
    } else if (TRANSPORT_LAYER_PROTOCOL == IPPROTO_UDP) {
        protocol_filter = new UDPFilter();
    }

    /* If protocol header is valid, then set protocol header */
    if (protocol_filter) {
        this->SetProtocol(protocol_filter);
    }

    this->protocol_header_->Parse(packet, start);
}

void TransportLayerFilter::Print() {
    std::cout << "Transport Layer Header:\n";
    this->protocol_header_->Print();
    std::cout << "\n";
}

uint TransportLayerFilter::GetHeaderSize() {
    return this->protocol_header_->GetHeaderSize();
}

TransportLayerFilter::~TransportLayerFilter() {
    delete this->protocol_header_;
}

/* ----- Utility Functions ----- */
std::vector<FilterInterface*> CreateLayerFilterArray() {
    std::vector<FilterInterface*> filters;

    EthernetLayerFilter* eth = new EthernetLayerFilter();
    filters.push_back(eth);

    NetworkLayerFilter* ip = new NetworkLayerFilter();
    filters.push_back(ip);

    TransportLayerFilter* tp = new TransportLayerFilter();
    filters.push_back(tp);

    return filters;
}

void FreeLayerFilterArray(std::vector<FilterInterface*>& filters) {
    std::vector<FilterInterface*>::iterator itr;

    for (itr = filters.begin(); itr != filters.end(); itr++) {
        delete *itr;
    }
}