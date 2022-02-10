/* Header file for including other standard headers and defining commands */
#ifndef INCLUDES_H
#define INCLUDES_H

#include <net/ethernet.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#define LIST_DEVICES "list"
#define DEVICE_ARG 'd'
#define FILTER_ARG 'f'

#endif