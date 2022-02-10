#! /bin/bash
# Build script for Netlyzer application

if [ ! -d "./build" ]
then
    mkdir build
fi

cd build
cmake ..
make