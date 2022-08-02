/* Util Function and Classes Header Declaration */
#ifndef UTILS_H
#define UTILS_H

#include "includes.h"
#include "network_filters.h"

/* Struct to hold Arg values */
struct ConfigValues {
    /* Device Name */
    std::string device_name_;
    /* Filter Expression */
    std::string filter_exp_;
    /* Path to read packets from in offline mode */
    std::string capture_file_path_;
    /* Path to export capture */
    std::string dump_file_path_;
    /* Number of packets to be read */
    uint packets_to_read_;
};

/* Struct to hold args for packet handler callback */
struct PacketArgs {
    /* Packet Count */
    uint packet_count_;
    /* Dump file Path. If not dumping, it's empty string */
    std::string dump_file_path_;
};

/* Takes a char buffer,size of buffer and returns a string in hexadecimal colon seperated form */
std::string ConvertToHexadecimal(u_char* buf, int buf_len);

/* Returns width of the terminal */
int GetTerminalWidth();

/* Prints a seperator the given number of times to the console */
void PrintSeperator(char sep, int count);

/* Create a packet handler function from passed function args */
void PacketHandler(u_char* args, const pcap_pkthdr* header, const u_char* packet);

#endif