/* Util Function and Classes Header Declaration */
#ifndef UTILS_H
#define UTILS_H

#include "includes.h"

/* Takes a char buffer,size of buffer and returns a string in hexadecimal colon seperated form */
std::string ConvertToHexadecimal(u_char* buf, int buf_len);

/* Returns width of the terminal */
int GetTerminalWidth();

/* Prints a seperator the given number of times to the console */
void PrintSeperator(char sep, int count);

/* Converts an int into 2 Bytes Hexadecimal Value */
int BtoHex2(uint16_t val);

#endif