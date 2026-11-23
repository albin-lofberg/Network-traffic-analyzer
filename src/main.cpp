#include <pcap/pcap.h> 

#include <exception>
#include <cstdio>
#include <iostream>

#include "pcap_capture.hpp"

int main(int argc, char** argv){
    if (argc != 2){
        std::cerr << "usage: too many or too few arguments";
        return 2;
    } 

    try {
        PcapCapture capture = PcapCapture::open_live(argv[1]);
        capture.run(10, [](const pcap_pkthdr& header, const u_char*)
        {
            std::printf("%ld.%06ld caplen=%u len=%u\n", 
            static_cast<long>(header.ts.tv_usec), header.caplen, header.len);
        });
    } catch (const std::exception& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    }
    return 0; 
}
