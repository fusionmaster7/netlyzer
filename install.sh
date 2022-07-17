#! /bin/bash
# Install script for netlyzer

sudo apt-get install libpcap-dev
bash ./build.sh
cd build
cp ./netlyzer /usr/local/bin
CURRENT_PATH=`pwd`
sudo ln -sf $CURRENT_PATH/netlyzer /usr/local/bin/netlyzer