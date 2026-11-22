#include <pcap/pcap.h> 

#include <iomanip>
#include <cstdio>
#include <iostream>

//called for every packet, prints one line describing packet
static void on_packet(u_char*, const pcap_pkthdr* header, const u_char*){
    std::cout << header->ts.tv_sec << '.' << std::setfill('0') << std::setw(6)
    << header->ts.tv_usec << " caplen" << header->caplen << " len" << header->len 
    << std::endl;
}

int main(int argc, char** argv){

    if (argc != 2){
        std::cerr << "usage: too many or too few arguments";
        return 2;
    } 

    char errbuf[PCAP_ERRBUF_SIZE] = {};

    pcap_t* handle = pcap_open_live(argv[1], 65535, 1, 1000, errbuf);
    if (handle == nullptr){
        std::cerr << "Can't open " << argv[1] << ": " << errbuf << std::endl;
        return 1;
    }

    //captures 10 packets, returns after 10 loops - result 0 if success
    const int result = pcap_loop(handle, 10, on_packet, nullptr);
    if (result == PCAP_ERROR){
        std::cerr << pcap_geterr(handle) << std::endl;
        return 1;
    }


    pcap_close(handle);
    return 0;
}