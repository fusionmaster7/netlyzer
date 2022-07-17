# Netlyzer
### Netlyzer is a simple packet analyzer for Linux written in C++

The application is currently in CLI format and supports the following features:

1. Capture packets live from device or from file.
2. Parse packet headers for the following layers:
   1. Data Link Layer
   2. Network Layer
   3. Transport Layer

### Installation Steps
Run ```install.sh``` script file

### How to run
1. Use the ```netlyzer -i``` command to run in interactive mode.
2. Use the ```netlyzer -d <interface>``` command to run the sniffer on a particular interface.