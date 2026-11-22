#include <pcap/pcap.h> 

#include <cstdio>
#include <iostream>

// Used to check if libpcap is installed and working properly
int main() {
    std::cout << pcap_lib_version() << std::endl;

    // Checks if libpcap can lookup list capture interfaces
    // prints the error and exits with code 1 if lookup fails
    char errbuf[PCAP_ERRBUF_SIZE] = {};
    pcap_if_t* alldevs = nullptr;
    if (pcap_findalldevs(&alldevs, errbuf) == PCAP_ERROR) {
        std::cerr << "Error finding devices: " << errbuf << std::endl;
        return 1;
    }

    for (const pcap_if_t* d = alldevs; d != nullptr; d = d->next){
        std::cout << d->name;
        if (d->description != nullptr){
            std::cout << " -" << d->description << "-";
        } 
        std::cout << std::endl;
    }

    pcap_freealldevs(alldevs);
    return 0;
}

