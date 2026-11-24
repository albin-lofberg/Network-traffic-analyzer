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

include(FetchContent)
FetchContent_Declare(
  CLI11
  GIT_REPOSITORY https://github.com/CLIUtils/CLI11.git
  GIT_TAG v2.4.2
)
FetchContent_MakeAvailable(CLI11)

add_executable(analyzer src/main.cpp src/pcap_capture.cpp src/decoder.cpp)
target_include_directories(analyzer PRIVATE ${PCAP_INCLUDE_DIR} src)
target_link_libraries(analyzer PRIVATE ${PCAP_LIBRARY})
target_compile_options(analyzer PRIVATE -Wall -Wextra -Wpedantic)

target_link_libraries(analyzer PRIVATE ${PCAP_LIBRARY} CLI11::CLI11)

# Unit tests for the decoder (no libpcap needed)
enable_testing()
add_executable(decoder_tests tests/test_decoder.cpp src/decoder.cpp)
target_include_directories(decoder_tests PRIVATE src)
target_compile_options(decoder_tests PRIVATE -Wall -Wextra -Wpedantic)
add_test(NAME decoder COMMAND decoder_tests)