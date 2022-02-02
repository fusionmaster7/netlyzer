cmake_minimum_required(VERSION 2.8)

project(netlyzer)

include_directories(./src/headers)

include(FindPCAP.cmake)

file(GLOB SOURCES src/*.cpp)


add_executable(netlyzer ${SOURCES})
target_link_libraries(netlyzer ${PCAP_LIBRARY})