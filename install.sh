#! /bin/bash
# Install script for netlyzer

cd build
cp ./netlyzer /usr/local/bin
cd ..
sudo ln -sf ./build/netlyzer /usr/local/bin/netlyzer