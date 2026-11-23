cmake_minimum_required(VERSION 3.10)
project(NetworkTrafficAnalyzer CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_path(PCAP_INCLUDE_DIR pcap/pcap.h)
find_library(PCAP_LIBRARY pcap)
if(NOT PCAP_INCLUDE_DIR OR NOT PCAP_LIBRARY)
    message(FATAL_ERROR "libcap not found. Install it with: sudo apt install libpcap-dev")
endif()


add_executable(analyzer src/main.cpp src/pcap_capture.cpp)
target_include_directories(analyzer PRIVATE ${PCAP_INCLUDE_DIR} src)
target_link_libraries(analyzer PRIVATE ${PCAP_LIBRARY})
target_compile_options(analyzer PRIVATE -Wall -Wextra -Wpedantic)
