# Netlyzer
### Netlyzer is a simple packet analyzer for Linux written in C++

The application is currently in CLI format and supports the following features:

1. Capture packets live from device or from file.
2. Parse packet headers for the following layers:
   1. Data Link Layer
   2. Network Layer
   3. Transport Layer

### Installation Steps
1. Run the ```build.sh``` script
2. Run the ```install.sh``` script
3. Start the application using ```netlyzer -d wlp2s0``` command from anywhere in your terminal.